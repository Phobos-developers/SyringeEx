#include "SyringeDebugger.h"

#include "CRC32.h"
#include "FindFile.h"
#include "Handle.h"
#include "Log.h"
#include "Support.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <numeric>
#include <set>
#include <vector>

#include <DbgHelp.h>

using namespace std;

// Log fatal setup failures without making optional export reads noisy.
[[noreturn]] static void ThrowMemoryError(char const* const operation,
    void const* const address, size_t const size, std::string const& exe)
{
    auto const error = GetLastError();
    auto const code = error ? error : ERROR_ERRORS_ENCOUNTERED;
    Log::WriteLine("SyringeDebugger: %s failed at %p (size=%zu, error=%lu).",
        operation, const_cast<void*>(address), size, static_cast<unsigned long>(code));
    throw_lasterror(code, exe);
}

void SyringeDebugger::DebugProcess(std::string_view const arguments)
{
    STARTUPINFO startupInfo{};
    startupInfo.cb = sizeof(startupInfo);

    SetEnvironmentVariable("_NO_DEBUG_HEAP", "1");

    auto command_line = '"' + exe + "\" ";
    command_line += arguments;

    if (CreateProcess(
        exe.c_str(), command_line.data(), nullptr, nullptr, false,
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
        nullptr, nullptr, &startupInfo, &pInfo) == FALSE)
    {
        throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
    }

    workingHandle = pInfo.hProcess;
}

bool SyringeDebugger::PatchMem(void* address, void const* buffer, DWORD size)
{
    return (WriteProcessMemory(workingHandle, address, buffer, size, nullptr) != FALSE);
}

bool SyringeDebugger::PatchCode(void* address, void const* buffer, DWORD size)
{
    return PatchMem(address, buffer, size)
        && FlushInstructionCache(workingHandle, address, size) != FALSE;
}

bool SyringeDebugger::ReadMem(void const* address, void* buffer, DWORD size)
{
    return (ReadProcessMemory(workingHandle, address, buffer, size, nullptr) != FALSE);
}

VirtualMemoryHandle SyringeDebugger::AllocMem(void* address, size_t size)
{
    if (VirtualMemoryHandle res{ workingHandle, address, size })
    {
        return res;
    }

    throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
}

void SyringeDebugger::MakeExecutable(VirtualMemoryHandle const& memory, size_t size)
{
    if (!memory.protect(size, PAGE_EXECUTE_READ))
    {
        ThrowMemoryError("VirtualProtectEx", memory.get(), size, exe);
    }
    if (!memory.flush_instruction_cache(size))
    {
        ThrowMemoryError("FlushInstructionCache", memory.get(), size, exe);
    }
}

bool SyringeDebugger::SetBP(void* address)
{
    // save overwritten code and set INT 3
    if (auto& opcode = Breakpoints[address].original_opcode; opcode == 0x00)
    {
        auto const buffer = INT3;
        ReadMem(address, &opcode, 1);
        return PatchCode(address, &buffer, 1);
    }

    return true;
}

DWORD __fastcall SyringeDebugger::RelativeOffset(void const* pFrom, void const* pTo)
{
    auto const from = reinterpret_cast<DWORD>(pFrom);
    auto const to = reinterpret_cast<DWORD>(pTo);

    return to - from;
}

// Resolve relative operands in an encoder request to absolute addresses.
static void ResolveRelativeOperands(
    ZydisEncoderRequest& req,
    ZydisDecodedInstruction const& instruction,
    ZydisDecodedOperand const* operands,
    ZyanU64 srcAddr)
{
    for (ZyanU8 i = 0; i < req.operand_count; ++i)
    {
        if (req.operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            ZyanU64 absAddr;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                    &instruction, &operands[i], srcAddr, &absAddr)))
            {
                req.operands[i].imm.u = absAddr;
            }
        }
        else if (req.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            ZyanU64 absAddr;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                    &instruction, &operands[i], srcAddr, &absAddr)))
            {
                req.operands[i].mem.displacement =
                    static_cast<ZyanI64>(absAddr);
            }
        }
    }
}

std::vector<BYTE> SyringeDebugger::RebuildInstructions(
    BYTE const* bytes, size_t size, DWORD originalAddr, DWORD newAddr,
    std::string_view const hookLibraries)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    std::string hookContext;
    if (!hookLibraries.empty())
    {
        hookContext = " in DLL(s): ";
        hookContext += hookLibraries;
    }

    // --- Pass 1: decode all instructions and classify relative branches ---

    struct InstructionInfo
    {
        size_t srcOffset;       // offset into original bytes
        ZyanU8 srcLength;       // original instruction length
        bool intraPrologue;     // relative branch targets within the prologue
        size_t targetSrcOffset; // source offset of branch target (intra-prologue only)
        size_t outputSize;      // size in the output buffer
        size_t outputOffset;    // offset within the output buffer
        std::optional<ZydisEncoderRequest> encoderReq; // cached encoder request (relative instrs only)
    };

    std::vector<InstructionInfo> infos;
    size_t tailOffset = size; // offset of undecoded tail, if any

    {
        size_t offset = 0;
        size_t outOff = 0;
        while (offset < size)
        {
            ZydisDecodedInstruction instruction;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            auto const srcAddr = static_cast<ZyanU64>(originalAddr + offset);

            if (ZYAN_FAILED(ZydisDecoderDecodeFull(
                    &decoder, bytes + offset, size - offset, &instruction, operands)))
            {
                Log::WriteLine(
                    __FUNCTION__ ": Failed to decode instruction at 0x%08X, "
                    "copying remaining %u bytes verbatim. This could mean "
                    "there is a faulty return 0 hook at 0x%08X%s.",
                    static_cast<DWORD>(srcAddr), static_cast<unsigned>(size - offset),
                    originalAddr, hookContext.c_str());

                tailOffset = offset;
                break;
            }

            InstructionInfo info{};
            info.srcOffset = offset;
            info.srcLength = instruction.length;
            info.outputSize = instruction.length; // default fallback
            info.intraPrologue = false;
            info.targetSrcOffset = 0;

            if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
            {
                // Only Jcc, JMP, and CALL have near (rel32) forms.
                // LOOP/LOOPE/LOOPNE/JCXZ/JECXZ/JRCXZ are rel8-only but
                // Zydis classifies them as COND_BR, so we must exclude
                // them by mnemonic.
                auto const cat = instruction.meta.category;
                auto const mn = instruction.mnemonic;
                bool const hasNearForm =
                    (cat == ZYDIS_CATEGORY_COND_BR
                        || cat == ZYDIS_CATEGORY_UNCOND_BR
                        || cat == ZYDIS_CATEGORY_CALL)
                    && mn != ZYDIS_MNEMONIC_LOOP
                    && mn != ZYDIS_MNEMONIC_LOOPE
                    && mn != ZYDIS_MNEMONIC_LOOPNE
                    && mn != ZYDIS_MNEMONIC_JCXZ
                    && mn != ZYDIS_MNEMONIC_JECXZ
                    && mn != ZYDIS_MNEMONIC_JRCXZ;

                // Find the immediate operand and resolve its absolute target.
                for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i)
                {
                    if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    {
                        ZyanU64 absAddr;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                                &instruction, &operands[i], srcAddr, &absAddr)))
                        {
                            // Check if target falls within the prologue.
                            if (absAddr >= originalAddr
                                && absAddr < originalAddr + size)
                            {
                                if (hasNearForm)
                                {
                                    info.intraPrologue = true;
                                    info.targetSrcOffset =
                                        static_cast<size_t>(absAddr - originalAddr);
                                }
                                else
                                {
                                    Log::WriteLine(
                                        __FUNCTION__ ": Relative instruction "
                                        "at 0x%08X has an intra-prologue target "
                                        "but no near encoding. Hook at 0x%08X%s "
                                        "may not work correctly.",
                                        static_cast<DWORD>(srcAddr), originalAddr,
                                        hookContext.c_str());
                                }
                            }
                        }
                        break;
                    }
                }

                // Build and cache the encoder request for pass 2.
                ZydisEncoderRequest req;
                if (!ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
                        &instruction, operands,
                        instruction.operand_count_visible, &req)))
                {
                    ResolveRelativeOperands(
                        req, instruction, operands, srcAddr);

                    if (hasNearForm)
                    {
                        // Force near encoding so output size is deterministic
                        // regardless of the final destination address.
                        req.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
                        req.branch_width = ZYDIS_BRANCH_WIDTH_32;
                    }

                    info.encoderReq = req;

                    if (hasNearForm)
                    {
                        // 6 bytes for Jcc near (0F 8x rel32), 5 bytes for JMP/CALL (E9/E8 rel32).
                        info.outputSize = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR)
                            ? 6u : 5u;
                    }
                }
            }

            info.outputOffset = outOff;
            outOff += info.outputSize;

            infos.push_back(info);
            offset += instruction.length;
        }
    }

    // --- Pass 2: emit relocated instructions ---

    std::vector<BYTE> result;
    result.reserve(size * 2);

    for (size_t idx = 0; idx < infos.size(); ++idx)
    {
        auto const& info = infos[idx];
        auto const srcAddr = static_cast<ZyanU64>(originalAddr + info.srcOffset);
        auto const dstAddr = static_cast<ZyanU64>(newAddr + result.size());

        if (!info.encoderReq)
        {
            result.insert(result.end(),
                bytes + info.srcOffset,
                bytes + info.srcOffset + info.srcLength);
            continue;
        }

        auto req = *info.encoderReq;

        if (info.intraPrologue)
        {
            // Map the immediate target to its relocated output offset.
            for (ZyanU8 i = 0; i < req.operand_count; ++i)
            {
                // For jumps within the prologue, find the instruction to which
                // the jump is, and substitute its new shifted absolute address
                if (req.operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    for (size_t j = 0; j < infos.size(); ++j)
                    {
                        if (infos[j].srcOffset == info.targetSrcOffset)
                        {
                            req.operands[i].imm.u = static_cast<ZyanU64>(
                                newAddr + infos[j].outputOffset);
                            break;
                        }
                    }
                    break;
                }
            }
        }

        BYTE encoded[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZyanUSize encodedLen = sizeof(encoded);

        if (ZYAN_FAILED(ZydisEncoderEncodeInstructionAbsolute(
                &req, encoded, &encodedLen, dstAddr)))
        {
            Log::WriteLine(
                __FUNCTION__ ": Failed to re-encode instruction at 0x%08X, "
                "copying %u bytes verbatim. This could mean there is a "
                "faulty return 0 hook at 0x%08X.",
                static_cast<DWORD>(srcAddr), info.srcLength,
                originalAddr);

            result.insert(result.end(),
                bytes + info.srcOffset,
                bytes + info.srcOffset + info.srcLength);
        }
        else
        {
            result.insert(result.end(), encoded, encoded + encodedLen);
        }
    }

    // Append any undecoded tail bytes verbatim.
    if (tailOffset < size)
        result.insert(result.end(), bytes + tailOffset, bytes + size);

    return result;
}

DWORD SyringeDebugger::HandleException(DEBUG_EVENT const& dbgEvent)
{
    auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
    auto const exceptAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;

    if (exceptCode == EXCEPTION_BREAKPOINT)
    {
        auto& threadInfo = Threads[dbgEvent.dwThreadId];
        HANDLE currentThread = threadInfo.Thread;
        CONTEXT context;

        context.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(currentThread, &context);

        // entry breakpoint
        if (bEntryBP)
        {
            bEntryBP = false;
            return DBG_CONTINUE;
        }

        // fix single step repetition issues
        if (context.EFlags & 0x100)
        {
            auto const buffer = INT3;
            context.EFlags &= ~0x100;
            if (!PatchCode(threadInfo.lastBP, &buffer, 1))
            {
                throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
            }
        }

        // load the hook DLLs and resolve hook and feature flag addresses. Each call into
        // the target costs two debug events, so the DLLs are loaded once each and every
        // address is then read from their loaded export tables; only what that cannot resolve
        // goes through GetProcAddress in the target
        if (!bDLLsLoaded)
        {
            // restore
            if (!PatchCode(exceptAddr, &Breakpoints[exceptAddr].original_opcode, 1))
            {
                throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
            }

            if (bLoaderStarted)
            {
                FinishLoaderCall(v_LoaderCalls[loaderNext++]);
            }

            bLoaderStarted = true;

            if (loaderNext == v_LoaderCalls.size() && !bExportsResolved)
            {
                bExportsResolved = true;
                ResolveFromExports();
            }

            if (loaderNext < v_LoaderCalls.size())
            {
                StartLoaderCall(v_LoaderCalls[loaderNext]);
                context.Eip = reinterpret_cast<DWORD>(GetLoaderCode());
            }
            else
            {
                Log::WriteLine(__FUNCTION__ ": Finished retrieving proc addresses.");

                if (!v_FeatureFlags.empty())
                {
                    Log::WriteLine(__FUNCTION__ ": Finished setting feature flags.");
                }

                bDLLsLoaded = true;

                context.Eip = reinterpret_cast<DWORD>(pcEntryPoint);
            }

            // single step mode
            context.EFlags |= 0x100;
            context.ContextFlags = CONTEXT_CONTROL;
            SetThreadContext(currentThread, &context);

            threadInfo.lastBP = exceptAddr;

            return DBG_CONTINUE;
        }

        if (exceptAddr == pcEntryPoint)
        {
            if (!bHooksCreated)
            {
                Log::WriteLine(__FUNCTION__ ": Creating code hooks.");

                // FS:[0x14] is a part of the Thread Information Block (TIB)
                // structure and is designated as the "arbitrary user pointer".
                // While Raymond Chen has mentioned that this field is "not safe"
                // to use for arbitrary purposes, this appears to not be the case,
                // judging by the article he cites as source (lol)

                // https://devblogs.microsoft.com/oldnewthing/20190418-00/?p=102428
                // https://web.archive.org/web/20250707201905/http://www.nynaeve.net/?p=98

                #define POPFD_POPAD \
                    0x9D, /* POPFD */ \
                    /* start POPAD replica */ \
                    0x5F, /* POP EDI */ \
                    0x5E, /* POP ESI */ \
                    0x5D, /* POP EBP */ \
                    0x5B, /* POP EBX (temporary storage for modified ESP) */ \
                    0x8B, 0x44, 0x24, 0x0C, /* MOV EAX, [ESP + 0xC] (restore EAX which is last in PUSHAD order) */ \
                    0x89, 0x5C, 0x24, 0x0C, /* MOV [ESP + 0xC], EBX (place ESP last) */ \
                    0x5B, /* POP EBX */ \
                    0x5A, /* POP EDX */ \
                    0x59, /* POP ECX */ \
                    0x5C /* POP ESP (restore ESP last thus not corrupting the stack pointer before all POPs are done) */ \
                    /* end POPAD replica */

                static BYTE const code_call[] =
                {
                    0x60, 0x9C, // PUSHAD, PUSHFD
                    0x68, INIT, INIT, INIT, INIT, // PUSH HookAddress
                    0x54, // PUSH ESP (final REGISTERS* argument)
                    0xE8, INIT, INIT, INIT, INIT, // CALL ProcAddress
                    0x83, 0xC4, 0x08, // ADD ESP, 8
                    0x64, /* FS segment prefix */ 0xA3, 0x14, 0x00, 0x00, 0x00, // MOV fs:0x14, EAX
                    0x64, /* FS segment prefix */ 0x83, 0x3D, 0x14, 0x00, 0x00, 0x00, 0x00, // CMP DWORD PTR fs:0x14, 0
                    0x74, 0x18, // JE proceed

                    // jmp_to_address:
                    POPFD_POPAD,
                    0x64, /* FS segment prefix */ 0xFF, 0x25, 0x14, 0x00, 0x00, 0x00, // JMP DWORD PTR fs:0x14

                    // proceed:
                    POPFD_POPAD,
                    // here will be the overwritten bytes and jump back
                };

                // return 0 hooks are chained, so this structure may repeat

                static BYTE const jmp_back[] = { 0xE9, INIT, INIT, INIT, INIT };
                static BYTE const jmp[] = { 0xE9, INIT, INIT, INIT, INIT };

                struct Site
                {
                    BYTE* address;
                    BreakpointInfo const* info;
                    size_t overridden;
                    size_t offset; // of its caller code in the allocation
                    size_t capacity;
                };

                std::vector<Site> sites;
                size_t total = 0;
                auto const callerLimit = std::min<size_t>(std::numeric_limits<DWORD>::max(),
                    std::vector<BYTE>{}.max_size());

                for (auto& it : Breakpoints)
                {
                    if (it.first == nullptr || it.first == pcEntryPoint)
                    {
                        continue;
                    }

                    auto const [count, overridden] = std::accumulate(
                        it.second.hooks.cbegin(), it.second.hooks.cend(),
                        std::make_pair(size_t{0}, size_t{0}), [](auto acc, auto const& hook)
                        {
                            if (hook.proc_address) {
                                if (acc.second < hook.num_overridden) {
                                    acc.second = hook.num_overridden;
                                }
                                acc.first++;
                            }
                            return acc; });

                    if (!count)
                    {
                        continue;
                    }

                    // Check each term before multiplying or adding. The whole block must
                    // also fit the DWORD size accepted by PatchMem.
                    auto const remaining = callerLimit - total;
                    if (remaining < sizeof(jmp_back)
                        || count > (remaining - sizeof(jmp_back)) / sizeof(code_call)
                        || overridden > (remaining - sizeof(jmp_back) - count * sizeof(code_call)) / 3)
                    {
                        Log::WriteLine("SyringeDebugger: Caller size overflow at %p (hooks=%zu, overridden=%zu, total=%zu).",
                            it.first, count, overridden, total);
                        throw_lasterror(ERROR_ARITHMETIC_OVERFLOW, exe);
                    }
                    // Relative instruction re-encoding may expand the overwritten bytes.
                    auto const capacity = count * sizeof(code_call) + sizeof(jmp_back) + overridden * 3;
                    sites.push_back({ static_cast<BYTE*>(it.first), &it.second, overridden, total, capacity });
                    total += capacity;
                }

                if (!sites.empty())
                {
                    // every caller is built here and written to one allocation in one go,
                    // instead of one allocation and write per hook site
                    pCallerCode = AllocMem(nullptr, total);
                    auto const base = static_cast<BYTE*>(pCallerCode.get());
                    std::vector<BYTE> callers(total, INT3);

                    auto const patchEnd = [](Site const& site)
                    {
                        return site.address + std::max(site.overridden, sizeof(jmp));
                    };

                    struct PreparedPatch
                    {
                        BYTE* address;
                        std::vector<BYTE> bytes;
                        std::vector<size_t> regionEnds;
                    };
                    std::vector<PreparedPatch> patches;

                    for (size_t first = 0; first < sites.size();)
                    {
                        // Batch within one region, but keep overlapping sites together
                        // across boundaries so each sees the previous sites' patches.
                        MEMORY_BASIC_INFORMATION region{};
                        if (!VirtualQueryEx(workingHandle, sites[first].address, &region, sizeof(region)))
                        {
                            ThrowMemoryError("VirtualQueryEx", sites[first].address, sizeof(region), exe);
                        }
                        auto regionEnd = static_cast<BYTE*>(region.BaseAddress) + region.RegionSize;

                        auto const runStart = sites[first].address;
                        auto runEnd = patchEnd(sites[first]);
                        auto last = first + 1;

                        while (last < sites.size()
                            && sites[last].address <= runEnd + MaxPatchGap
                            && (patchEnd(sites[last]) <= regionEnd || sites[last].address < runEnd))
                        {
                            runEnd = std::max(runEnd, patchEnd(sites[last]));
                            ++last;
                        }

                        std::vector<BYTE> memory(static_cast<size_t>(runEnd - runStart));
                        std::vector<size_t> regionEnds;
                        for (size_t offset = 0; offset < memory.size();)
                        {
                            auto const end = std::min(runEnd, regionEnd);
                            auto const size = static_cast<DWORD>(end - (runStart + offset));
                            if (!ReadMem(runStart + offset, memory.data() + offset, size))
                            {
                                ThrowMemoryError("ReadProcessMemory", runStart + offset, size, exe);
                            }
                            offset += size;
                            regionEnds.push_back(offset);
                            if (offset < memory.size())
                            {
                                if (!VirtualQueryEx(workingHandle, runStart + offset, &region, sizeof(region)))
                                {
                                    ThrowMemoryError("VirtualQueryEx", runStart + offset, sizeof(region), exe);
                                }
                                regionEnd = static_cast<BYTE*>(region.BaseAddress) + region.RegionSize;
                            }
                        }

                        for (auto i = first; i < last; ++i)
                        {
                            auto const& site = sites[i];
                            auto const original = memory.data() + (site.address - runStart);
                            auto const callerStart = callers.data() + site.offset;
                            auto const callerEnd = callerStart + site.capacity;
                            auto p_code = callerStart;

                            auto const remote = [&](BYTE const* local)
                            {
                                return base + (local - callers.data());
                            };

                            // write caller code
                            for (auto const& hook : site.info->hooks)
                            {
                                if (hook.proc_address)
                                {
                                    ApplyPatch(p_code, code_call);		    // code
                                    ApplyPatch(p_code + 0x03, site.address); // PUSH HookAddress

                                    auto const rel = RelativeOffset(remote(p_code + 0x0D), hook.proc_address);
                                    ApplyPatch(p_code + 0x09, rel); // CALL

                                    p_code += sizeof(code_call);
                                }
                            }

                            // rebuild overridden bytes, adjusting relative addresses
                            if (site.overridden)
                            {
                                std::set<std::string_view> rebuildLibraries;
                                for (auto const& hook : site.info->hooks)
                                {
                                    if (hook.proc_address && hook.num_overridden == site.overridden)
                                    {
                                        rebuildLibraries.emplace(hook.lib);
                                    }
                                }

                                std::string rebuildLibraryNames;
                                for (auto const library : rebuildLibraries)
                                {
                                    if (!rebuildLibraryNames.empty())
                                    {
                                        rebuildLibraryNames += ", ";
                                    }
                                    rebuildLibraryNames += '"';
                                    rebuildLibraryNames += library;
                                    rebuildLibraryNames += '"';
                                }

                                auto const originalAddr = reinterpret_cast<DWORD>(site.address);
                                auto const newAddr = reinterpret_cast<DWORD>(remote(p_code));

                                auto rebuilt = RebuildInstructions(
                                    original, site.overridden, originalAddr, newAddr,
                                    rebuildLibraryNames);

                                // Leave room for the jump back inside this site's slot.
                                auto const remaining = static_cast<size_t>(callerEnd - p_code);
                                if (remaining < sizeof(jmp_back) || rebuilt.size() > remaining - sizeof(jmp_back))
                                {
                                    Log::WriteLine("SyringeDebugger: Caller buffer too small at %p (rebuilt=%zu, remaining=%zu, jump=%zu).",
                                        site.address, rebuilt.size(), remaining, sizeof(jmp_back));
                                    throw_lasterror(ERROR_INSUFFICIENT_BUFFER, exe);
                                }
                                std::memcpy(p_code, rebuilt.data(), rebuilt.size());
                                p_code += rebuilt.size();
                            }

                            // write the jump back
                            auto const rel = RelativeOffset(remote(p_code + 0x05), site.address + 0x05);
                            ApplyPatch(p_code, jmp_back);
                            ApplyPatch(p_code + 0x01, rel);
                            p_code += sizeof(jmp_back);

                            // patch original code
                            auto const rel2 = RelativeOffset(site.address + 5, remote(callerStart));
                            std::memset(original, NOP, std::max(site.overridden, sizeof(jmp)));
                            ApplyPatch(original, jmp);
                            ApplyPatch(original + 0x01, rel2);
                        }

                        patches.push_back({ runStart, std::move(memory), std::move(regionEnds) });

                        first = last;
                    }

                    if (!PatchMem(base, callers.data(), static_cast<DWORD>(callers.size())))
                    {
                        ThrowMemoryError("WriteProcessMemory", base, callers.size(), exe);
                    }
                    MakeExecutable(pCallerCode, total);

                    // Publish jumps only when all callers are ready and executable.
                    for (auto const& patch : patches)
                    {
                        size_t offset = 0;
                        for (auto const end : patch.regionEnds)
                        {
                            if (!PatchCode(patch.address + offset, patch.bytes.data() + offset, static_cast<DWORD>(end - offset)))
                            {
                                ThrowMemoryError("PatchCode", patch.address + offset, end - offset, exe);
                            }
                            offset = end;
                        }
                    }
                }

                Log::Flush();

                bHooksCreated = true;
            }

            // restore
            if (!PatchCode(exceptAddr, &Breakpoints[exceptAddr].original_opcode, 1))
            {
                throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
            }

            // single step mode
            context.EFlags |= 0x100;
            --context.Eip;

            context.ContextFlags = CONTEXT_CONTROL;
            SetThreadContext(currentThread, &context);

            threadInfo.lastBP = exceptAddr;

            return DBG_CONTINUE;
        }
        else
        {
            // could be a Debugger class breakpoint to call a patching function!

            context.ContextFlags = CONTEXT_CONTROL;
            SetThreadContext(currentThread, &context);

            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }
    else if (exceptCode == EXCEPTION_SINGLE_STEP)
    {
        auto const buffer = INT3;
        auto const& threadInfo = Threads[dbgEvent.dwThreadId];
        if (!PatchCode(threadInfo.lastBP, &buffer, 1))
        {
            throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
        }

        HANDLE hThread = threadInfo.Thread;
        CONTEXT context;

        context.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hThread, &context);

        context.EFlags &= ~0x100;

        context.ContextFlags = CONTEXT_CONTROL;
        SetThreadContext(hThread, &context);

        return DBG_CONTINUE;
    }
    else
    {
        Log::WriteLine(
            __FUNCTION__ ": Exception (Code: 0x%08X at 0x%08X)!", exceptCode,
            exceptAddr);

        if (!bAVLogged)
        {
            // Log::WriteLine(__FUNCTION__ ": ACCESS VIOLATION at 0x%08X!", exceptAddr);
            auto const& threadInfo = Threads[dbgEvent.dwThreadId];
            HANDLE currentThread = threadInfo.Thread;

            char const* access = nullptr;
            switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0])
            {
            case 0:
                access = "read from";
                break;
            case 1:
                access = "write to";
                break;
            case 8:
                access = "execute";
                break;
            }

            Log::WriteLine("\tThe process tried to %s 0x%08X.",
                access,
                dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]);

            CONTEXT context;
            context.ContextFlags = CONTEXT_FULL;
            GetThreadContext(currentThread, &context);

            Log::WriteLine();
            Log::WriteLine("Registers:");
            Log::WriteLine("\tEAX = 0x%08X\tECX = 0x%08X\tEDX = 0x%08X",
                context.Eax, context.Ecx, context.Edx);
            Log::WriteLine("\tEBX = 0x%08X\tESP = 0x%08X\tEBP = 0x%08X",
                context.Ebx, context.Esp, context.Ebp);
            Log::WriteLine("\tESI = 0x%08X\tEDI = 0x%08X\tEIP = 0x%08X",
                context.Esi, context.Edi, context.Eip);
            Log::WriteLine();

            Log::WriteLine("\tStack dump:");
            auto const esp = reinterpret_cast<DWORD*>(context.Esp);
            for (auto p = esp; p < &esp[0x100]; ++p)
            {
                DWORD dw;
                if (ReadMem(p, &dw, 4))
                {
                    Log::WriteLine("\t0x%08X:\t0x%08X", p, dw);
                }
                else
                {
                    Log::WriteLine("\t0x%08X:\t(could not be read)", p);
                }
            }
            Log::WriteLine();

#if 0
            Log::WriteLine("Making crash dump:\n");
            MINIDUMP_EXCEPTION_INFORMATION expParam;
            expParam.ThreadId = dbgEvent.dwThreadId;
            EXCEPTION_POINTERS ep;
            ep.ExceptionRecord = const_cast<PEXCEPTION_RECORD>(&dbgEvent.u.Exception.ExceptionRecord);
            ep.ContextRecord = &context;
            expParam.ExceptionPointers = &ep;
            expParam.ClientPointers = FALSE;

            wchar_t filename[MAX_PATH];
            wchar_t path[MAX_PATH];
            SYSTEMTIME time;

            GetLocalTime(&time);
            GetCurrentDirectoryW(MAX_PATH, path);

            swprintf(filename, MAX_PATH, L"%s\\syringe.crashed.%04u%02u%02u-%02u%02u%02u.dmp",
                path, time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

            HANDLE dumpFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, nullptr);

            MINIDUMP_TYPE type = (MINIDUMP_TYPE)MiniDumpWithFullMemory;

            MiniDumpWriteDump(pInfo.hProcess, dbgEvent.dwProcessId, dumpFile, type, &expParam, nullptr, nullptr);
            CloseHandle(dumpFile);

            Log::WriteLine("Crash dump generated.\n");
#endif

            bAVLogged = true;
        }

        return DBG_EXCEPTION_NOT_HANDLED;
    }

}

void SyringeDebugger::Run(std::string_view const arguments)
{
    Log::WriteLine(
        __FUNCTION__ ": Running process to debug. cmd = \"%s %.*s\"",
        exe.c_str(), printable(arguments));
    DebugProcess(arguments);

    // write DLL loader code
    Log::WriteLine(__FUNCTION__ ": Writing DLL loader & caller code...");

    static constexpr BYTE cLoadLibrary[] = {
        0x50,								// push eax
        0x51,								// push ecx
        0x52,								// push edx
        0x68, INIT, INIT, INIT, INIT,		// push offset pdLibName
        0xFF, 0x15, INIT, INIT, INIT, INIT, // call pImLoadLibrary
        0xA3, INIT, INIT, INIT, INIT,		// mov pdModuleBase, eax
        0x85, 0xC0,							// test eax, eax
        0x74, 0x0C,							// jz
        0x68, INIT, INIT, INIT, INIT,		// push offset pdProcName
        0x50,								// push eax
        0xFF, 0x15, INIT, INIT, INIT, INIT, // call pdImGetProcAddress
        0xA3, INIT, INIT, INIT, INIT,		// mov pdProcAddress, eax
        0x5A,								// pop edx
        0x59,								// pop ecx
        0x58,								// pop eax
        INT3, NOP							// int3 and some padding
    };

    auto code = std::to_array(cLoadLibrary);
    pLoaderCode = AllocMem(nullptr, code.size());
    pExchangeData = AllocMem(nullptr, sizeof(ExchangeData));

    ApplyPatch(code.data() + 0x04, &GetData()->LibName);
    ApplyPatch(code.data() + 0x0A, pImLoadLibrary);
    ApplyPatch(code.data() + 0x0F, &GetData()->ModuleBase);
    ApplyPatch(code.data() + 0x18, &GetData()->ProcName);
    ApplyPatch(code.data() + 0x1F, pImGetProcAddress);
    ApplyPatch(code.data() + 0x24, &GetData()->ProcAddress);
    if (!PatchMem(pLoaderCode, code.data(), code.size()))
    {
        throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
    }
    MakeExecutable(pLoaderCode, code.size());

    Log::WriteLine(__FUNCTION__ ": pcLoadLibrary = 0x%08X", GetLoaderCode());

    // breakpoints for DLL loading and proc address retrieving
    bDLLsLoaded = false;
    bHooksCreated = false;

    // first load every hook DLL once; ResolveFromExports adds calls for what it can't resolve
    v_LoaderCalls.clear();
    for (size_t i = 0; i < v_Libraries.size(); ++i)
    {
        v_LoaderCalls.push_back({ i, "" });
    }

    loaderNext = 0;
    bLoaderStarted = false;
    bExportsResolved = false;

    // set breakpoint
    if (!SetBP(pcEntryPoint))
    {
        throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
    }

    DEBUG_EVENT dbgEvent;
    ResumeThread(pInfo.hThread);

    bAVLogged = false;

    Log::WriteLine(__FUNCTION__ ": Entering debug loop...");

    auto exit_code = static_cast<DWORD>(-1);

    while (true)
    {
        WaitForDebugEvent(&dbgEvent, INFINITE);

        DWORD continueStatus = DBG_CONTINUE;
        bool wasSingleStep = false;

        switch (dbgEvent.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            workingHandle = dbgEvent.u.CreateProcessInfo.hProcess;
            Threads.emplace(dbgEvent.dwThreadId, dbgEvent.u.CreateProcessInfo.hThread);
            CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            Threads.emplace(dbgEvent.dwThreadId, dbgEvent.u.CreateThread.hThread);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            if (auto const it = Threads.find(dbgEvent.dwThreadId); it != Threads.end())
            {
                it->second.Thread.release();
                Threads.erase(it);
            }
            break;

        case EXCEPTION_DEBUG_EVENT:
            continueStatus = HandleException(dbgEvent);
            wasSingleStep = (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP);
            break;

        case LOAD_DLL_DEBUG_EVENT:
            CloseHandle(dbgEvent.u.LoadDll.hFile);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            break;
        }

        if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            exit_code = dbgEvent.u.ExitProcess.dwExitCode;
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
            break;
        }
        else if (dbgEvent.dwDebugEventCode == RIP_EVENT)
        {
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
            break;
        }

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);

        if (bDetachWhenDone && bHooksCreated && wasSingleStep)
        {
            Log::WriteLine(__FUNCTION__ ": Hooks placed, detaching debugger.");

            if (!DebugActiveProcessStop(dbgEvent.dwProcessId))
                Log::WriteLine(__FUNCTION__ ": DebugActiveProcessStop failed (%u).", GetLastError());

            break;
        }
    }

    workingHandle = nullptr;

    if (bWaitForProcessEnd)
    {
        Log::WriteLine(__FUNCTION__ ": Waiting for process to exit...");

        WaitForSingleObject(pInfo.hProcess, INFINITE);

        if (!GetExitCodeProcess(pInfo.hProcess, &exit_code))
        {
            Log::WriteLine(__FUNCTION__ ": Failed to get process exit code!");
        }
    }

    CloseHandle(pInfo.hProcess);

    Log::WriteLine(
        __FUNCTION__ ": Done with exit code %X (%u).", exit_code, exit_code);
    Log::WriteLine();
}

void SyringeDebugger::StartLoaderCall(LoaderCall const& call)
{
    ExchangeData request{};
    strncpy_s(request.LibName, v_Libraries[call.library].name.c_str(), _TRUNCATE);
    strncpy_s(request.ProcName, call.proc.c_str(), _TRUNCATE);

    if (!PatchMem(GetData(), &request, sizeof(request)))
    {
        ThrowMemoryError("WriteProcessMemory", GetData(), sizeof(request), exe);
    }
}

void SyringeDebugger::FinishLoaderCall(LoaderCall const& call)
{
    void* results[2] = {};
    if (!ReadMem(&GetData()->ModuleBase, results, sizeof(results)))
    {
        ThrowMemoryError("ReadProcessMemory", &GetData()->ModuleBase, sizeof(results), exe);
    }
    auto const module = results[0];
    auto const address = results[1];

    if (call.hook)
    {
        call.hook->proc_address = address;

        if (!address)
        {
            Log::WriteLine(
                __FUNCTION__ ": Could not retrieve ProcAddress for: %s - %s",
                call.hook->lib, call.hook->proc);
        }
    }
    else if (call.flag)
    {
        ApplyFeatureFlag(*call.flag, address);
    }
    else
    {
        v_Libraries[call.library].module = module;

        if (!module)
        {
            Log::WriteLine(__FUNCTION__ ": Could not load \"%s\".", v_Libraries[call.library].name.c_str());
        }
    }
}

// Read one snapshot of the loaded module's export directory. If its tables live
// outside the directory or cannot be read, let GetProcAddress resolve the symbols.
bool SyringeDebugger::ReadModuleExports(HookLibrary& library)
{
    library.exports.clear();
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS nt{};
    auto const base = static_cast<BYTE*>(library.module);
    if (!ReadMem(base, &dos, sizeof(dos))
        || dos.e_magic != IMAGE_DOS_SIGNATURE
        || dos.e_lfanew < 0
        || !ReadMem(base + dos.e_lfanew, &nt, sizeof(nt))
        || nt.Signature != IMAGE_NT_SIGNATURE
        || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC
        || nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
    {
        return false;
    }

    auto const& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress && !dir.Size)
    {
        return true;
    }
    auto const imageSize = nt.OptionalHeader.SizeOfImage;
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY)
        || dir.VirtualAddress >= imageSize || dir.Size > imageSize - dir.VirtualAddress)
    {
        return false;
    }

    std::vector<BYTE> bytes(dir.Size);
    if (!ReadMem(base + dir.VirtualAddress, bytes.data(), dir.Size))
    {
        return false;
    }

    // Subtraction-based checks avoid overflow in RVA and array-size arithmetic.
    auto const contains = [&](DWORD rva, size_t count, size_t elementSize)
    {
        if (rva < dir.VirtualAddress)
        {
            return false;
        }
        size_t const offset = rva - dir.VirtualAddress;
        return offset <= bytes.size() && count <= (bytes.size() - offset) / elementSize;
    };

    IMAGE_EXPORT_DIRECTORY exports{};
    std::memcpy(&exports, bytes.data(), sizeof(exports));
    if (!exports.NumberOfNames)
    {
        return true;
    }
    if (!contains(exports.AddressOfNames, exports.NumberOfNames, sizeof(DWORD))
        || !contains(exports.AddressOfNameOrdinals, exports.NumberOfNames, sizeof(WORD))
        || !contains(exports.AddressOfFunctions, exports.NumberOfFunctions, sizeof(DWORD)))
    {
        return false;
    }

    for (DWORD i = 0; i < exports.NumberOfNames; ++i)
    {
        DWORD nameRva;
        WORD ordinal;
        DWORD rva;
        std::memcpy(&nameRva, bytes.data() + (exports.AddressOfNames - dir.VirtualAddress) + i * sizeof(DWORD), sizeof(nameRva));
        std::memcpy(&ordinal, bytes.data() + (exports.AddressOfNameOrdinals - dir.VirtualAddress) + i * sizeof(WORD), sizeof(ordinal));
        if (ordinal >= exports.NumberOfFunctions || !contains(nameRva, 1, 1))
        {
            return false;
        }
        std::memcpy(&rva, bytes.data() + (exports.AddressOfFunctions - dir.VirtualAddress) + ordinal * sizeof(DWORD), sizeof(rva));
        if (rva >= imageSize)
        {
            return false;
        }
        auto const name = reinterpret_cast<char const*>(bytes.data() + (nameRva - dir.VirtualAddress));
        auto const end = static_cast<char const*>(std::memchr(name, 0, bytes.size() - (nameRva - dir.VirtualAddress)));
        if (!end)
        {
            return false;
        }
        bool const forwarded = rva >= dir.VirtualAddress && rva - dir.VirtualAddress < dir.Size;
        library.exports.emplace(std::string(name, end), PEExport{ rva, forwarded });
    }
    return true;
}

void SyringeDebugger::ResolveFromExports()
{
    std::unordered_map<std::string_view, size_t> byName;
    std::vector<bool> usable(v_Libraries.size());

    for (size_t i = 0; i < v_Libraries.size(); ++i)
    {
        auto& library = v_Libraries[i];
        byName.emplace(library.name, i);
        usable[i] = library.module && ReadModuleExports(library);

        if (library.module && !usable[i])
        {
            Log::WriteLine(
                __FUNCTION__ ": Could not read exports from loaded \"%s\"; resolving them one by one.",
                library.name.c_str());
        }
    }

    // an address, null where GetProcAddress would return null, or nothing where only
    // GetProcAddress in the target can tell (a forwarded export, or an unreadable export directory)
    auto const resolve = [&](size_t const i, char const* const name) -> std::optional<void*>
    {
        auto const& library = v_Libraries[i];

        if (!library.module)
        {
            return nullptr;
        }

        if (!usable[i])
        {
            return std::nullopt;
        }

        auto const it = library.exports.find(name);
        if (it == library.exports.end() || !it->second.RVA)
        {
            return nullptr;
        }

        if (it->second.Forwarded)
        {
            return std::nullopt;
        }

        return static_cast<BYTE*>(library.module) + it->second.RVA;
    };

    for (auto const hook : v_AllHooks)
    {
        auto const i = byName.at(hook->lib);

        if (auto const address = resolve(i, hook->proc))
        {
            hook->proc_address = *address;

            if (!hook->proc_address)
            {
                Log::WriteLine(
                    __FUNCTION__ ": Could not retrieve ProcAddress for: %s - %s",
                    hook->lib, hook->proc);
            }
        }
        else
        {
            v_LoaderCalls.push_back({ i, hook->proc, hook });
        }
    }

    if (!v_FeatureFlags.empty())
    {
        Log::WriteLine(__FUNCTION__ ": Starting feature flags resolution...");
    }

    for (auto const& flag : v_FeatureFlags)
    {
        auto const i = byName.at(flag.lib);

        if (auto const address = resolve(i, flag.symbol))
        {
            ApplyFeatureFlag(flag, *address);
        }
        else
        {
            v_LoaderCalls.push_back({ i, flag.symbol, nullptr, &flag });
        }
    }
}

void SyringeDebugger::ApplyFeatureFlag(FeatureFlagEntry const& flag, void* const address)
{
    if (address)
    {
        BYTE const trueVal = 1;
        if (!PatchMem(address, &trueVal, 1))
        {
            ThrowMemoryError("WriteProcessMemory", address, 1, exe);
        }
        Log::WriteLine(
            __FUNCTION__ ": Set feature flag \"%s\" in \"%s\" at 0x%08X",
            flag.symbol, flag.lib, address);
    }
    else
    {
        Log::WriteLine(
            __FUNCTION__ ": Feature flag \"%s\" not exported by \"%s\", skipping.",
            flag.symbol, flag.lib);
    }
}

void SyringeDebugger::RemoveBP(LPVOID const address, bool const restoreOpcode)
{
    if (auto const i = Breakpoints.find(address); i != Breakpoints.end())
    {
        if (restoreOpcode)
        {
            if (!PatchCode(address, &i->second.original_opcode, 1))
            {
                throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
            }
        }

        Breakpoints.erase(i);
    }
}

void SyringeDebugger::RetrieveInfo()
{
    Log::WriteLine(
        __FUNCTION__ ": Retrieving info from the executable file...");

    try
    {
        PortableExecutable pe{ exe };
        auto const dwImageBase = pe.GetImageBase();

        // creation time stamp
        dwTimeStamp = pe.GetPEHeader().FileHeader.TimeDateStamp;

        // entry point
        pcEntryPoint = reinterpret_cast<void*>(dwImageBase + pe.GetPEHeader().OptionalHeader.AddressOfEntryPoint);

        // get imports
        pImLoadLibrary = nullptr;
        pImGetProcAddress = nullptr;

        for (auto const& import : pe.GetImports())
        {
            if (_strcmpi(import.Name.c_str(), "KERNEL32.DLL") == 0)
            {
                for (auto const& thunk : import.vecThunkData)
                {
                    if (_strcmpi(thunk.Name.c_str(), "GETPROCADDRESS") == 0)
                    {
                        pImGetProcAddress = reinterpret_cast<void*>(dwImageBase + thunk.Address);
                    }
                    else if (_strcmpi(thunk.Name.c_str(), "LOADLIBRARYA") == 0)
                    {
                        pImLoadLibrary = reinterpret_cast<void*>(dwImageBase + thunk.Address);
                    }
                }
            }
        }
    }
    catch (...)
    {
        Log::WriteLine(__FUNCTION__ ": Failed to open the executable!");

        throw;
    }

    if (!pImGetProcAddress || !pImLoadLibrary)
    {
        Log::WriteLine(
            __FUNCTION__ ": ERROR: Either a LoadLibraryA or a GetProcAddress "
            "import could not be found!");

        throw_lasterror_or(ERROR_PROC_NOT_FOUND, exe);
    }

    // read meta information: size and checksum
    if (ifstream is{ exe, ifstream::binary })
    {
        is.seekg(0, ifstream::end);
        dwExeSize = static_cast<DWORD>(is.tellg());
        is.seekg(0, ifstream::beg);

        CRC32 crc;
        char buffer[0x1000];
        while (auto const read = is.read(buffer, std::size(buffer)).gcount())
        {
            crc.compute(buffer, read);
        }
        dwExeCRC = crc.value();
    }

    Log::WriteLine(__FUNCTION__ ": Executable information successfully retrieved.");
    Log::WriteLine("\texe = %s", exe.c_str());
    Log::WriteLine("\tpImLoadLibrary = 0x%08X", pImLoadLibrary);
    Log::WriteLine("\tpImGetProcAddress = 0x%08X", pImGetProcAddress);
    Log::WriteLine("\tpcEntryPoint = 0x%08X", pcEntryPoint);
    Log::WriteLine("\tdwExeSize = 0x%08X", dwExeSize);
    Log::WriteLine("\tdwExeCRC = 0x%08X", dwExeCRC);
    Log::WriteLine("\tdwTimestamp = 0x%08X", dwTimeStamp);
    Log::WriteLine();

    Log::WriteLine(__FUNCTION__ ": Opening %s to determine imports.", exe.c_str());
}

void SyringeDebugger::FindDLLs()
{
    Breakpoints.clear();

    for (const auto& dll : dlls)
    {
        Log::WriteLine(__FUNCTION__ ": Searching for DLLs matching \"%s\"...", dll.c_str());

        for (auto file = FindFile(dll.c_str()); file; ++file)
        {
            std::string_view const fn(file->cFileName);

            // Log::WriteLine(
            //	__FUNCTION__ ": Potential DLL: \"%.*s\"", printable(fn));

            try
            {
                PortableExecutable const DLL{ fn };
                HookBuffer buffer;

                auto canLoad = false;
                if (auto const hooks = DLL.FindSection(".syhks00"))
                {
                    canLoad = ParseHooksSection(DLL, *hooks, buffer);
                }
                else
                {
                    canLoad = ParseInjFileHooks(fn, buffer);
                }

                if (canLoad)
                {
                    Log::WriteLine(__FUNCTION__ ": Recognized DLL: \"%.*s\"", printable(fn));

                    if (auto const res = Handshake(DLL.GetFilename(), static_cast<int>(buffer.count), buffer.checksum.value()))
                    {
                        canLoad = *res;
                    }
                    else if (auto const hosts = DLL.FindSection(".syexe00"))
                    {
                        canLoad = CanHostDLL(DLL, *hosts);
                    }
                }

                if (canLoad)
                {
                    for (auto const& it : buffer.hooks)
                    {
                        auto const eip = it.first;
                        auto& h = Breakpoints[eip];
                        h.original_opcode = 0x00;
                        h.hooks.insert(
                            h.hooks.end(), it.second.begin(), it.second.end());
                    }
                }
                else if (!buffer.hooks.empty())
                {
                    Log::WriteLine(__FUNCTION__ ": DLL load was prevented: \"%.*s\"", printable(fn));
                }
            }
            catch (...)
            {
                // Log::WriteLine(
                //	__FUNCTION__ ": DLL Parse failed: \"%.*s\"", printable(fn));
            }
        }
    }

    // summarize all hooks
    v_AllHooks.clear();
    for (auto& it : Breakpoints)
    {
        for (auto& i : it.second.hooks)
        {
            v_AllHooks.push_back(&i);
        }
    }

    Log::WriteLine(__FUNCTION__ ": Done (%d hooks added).", v_AllHooks.size());

    // build feature flag entries for each unique DLL
    v_FeatureFlags.clear();
    v_Libraries.clear();
    {
        std::set<std::string> uniqueLibs;
        for (auto const& hook : v_AllHooks)
        {
            if (uniqueLibs.insert(hook->lib).second)
            {
                for (auto const& flagName : FeatureFlagNames)
                {
                    FeatureFlagEntry entry{};
                    strncpy_s(entry.lib, hook->lib, MaxNameLength - 1);
                    flagName.copy(entry.symbol, MaxNameLength - 1);
                    v_FeatureFlags.push_back(entry);
                }

                auto& library = v_Libraries.emplace_back();
                library.name = hook->lib;
            }
        }
    }

    Log::WriteLine(
        __FUNCTION__ ": %d feature flag entries prepared.",
        v_FeatureFlags.size());
    Log::WriteLine();
}

bool SyringeDebugger::ParseInjFileHooks(
    std::string_view const lib, HookBuffer& hooks)
{
    auto const inj = std::string(lib) + ".inj";

    if (auto const file = FileHandle(_fsopen(inj.c_str(), "r", _SH_DENYWR)))
    {
        constexpr auto Size = 0x100;
        char line[Size];
        while (fgets(line, Size, file))
        {
            if (*line != ';' && *line != '\r' && *line != '\n')
            {
                void* eip = nullptr;
                auto n_over = 0u;
                char func[MaxNameLength];
                func[0] = '\0';

                // parse the line (length is optional, defaults to 0)
                if (sscanf_s(
                    line, "%p = %[^ \t;,\r\n] , %x", &eip, func,
                    static_cast<unsigned int>(MaxNameLength), &n_over) >= 2)
                {
                    hooks.add(eip, lib, func, static_cast<size_t>(n_over));
                }
            }
        }

        return true;
    }

    return false;
}

bool SyringeDebugger::CanHostDLL(
    PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hosts) const
{
    constexpr auto const Size = sizeof(hostdecl);
    auto const base = DLL.GetImageBase();

    auto const begin = hosts.PointerToRawData;
    auto const end = begin + hosts.SizeOfRawData;

    std::string hostName;
    for (auto ptr = begin; ptr < end; ptr += Size)
    {
        hostdecl h;
        if (DLL.ReadBytes(ptr, Size, &h))
        {
            if (h.hostNamePtr)
            {
                auto const rawNamePtr = DLL.VirtualToRaw(h.hostNamePtr - base);
                if (DLL.ReadCString(rawNamePtr, hostName))
                {
                    hostName += ".exe";
                    if (!_strcmpi(hostName.c_str(), exe.c_str()))
                    {
                        return true;
                    }
                }
            }
        }
        else
        {
            break;
        }
    }
    return false;
}

bool SyringeDebugger::ParseHooksSection(
    PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hooks,
    HookBuffer& buffer)
{
    constexpr auto const Size = sizeof(hookdecl);
    auto const base = DLL.GetImageBase();
    auto const filename = std::string_view(DLL.GetFilename());

    auto const begin = hooks.PointerToRawData;
    auto const end = begin + hooks.SizeOfRawData;

    std::string hookName;
    for (auto ptr = begin; ptr < end; ptr += Size)
    {
        hookdecl h;
        if (DLL.ReadBytes(ptr, Size, &h))
        {
            // msvc linker inserts arbitrary padding between variables that come
            // from different translation units
            if (h.hookNamePtr)
            {
                auto const rawNamePtr = DLL.VirtualToRaw(h.hookNamePtr - base);
                if (DLL.ReadCString(rawNamePtr, hookName))
                {
                    auto const eip = reinterpret_cast<void*>(h.hookAddr);
                    buffer.add(eip, filename, hookName, h.hookSize);
                }
            }
        }
        else
        {
            Log::WriteLine(__FUNCTION__ ": Bytes read failed");
            return false;
        }
    }

    return true;
}

// check whether the library wants to be included. if it exports a special
// function, we initiate a handshake. if it fails, or the dll opts out,
// the hooks aren't included. if the function is not exported, we have to
// rely on other methods.
std::optional<bool> SyringeDebugger::Handshake(
    char const* const lib, int const hooks, unsigned int const crc)
{
    std::optional<bool> ret;

    if (!bHandshakes)
    {
        Log::WriteLine(__FUNCTION__ ": Skipping handshake for DLL: \"%s\"", lib);
        return ret;
    }

    if (auto const hLib = ModuleHandle(LoadLibrary(lib)))
    {
        if (auto const func = reinterpret_cast<SYRINGEHANDSHAKEFUNC>(
            GetProcAddress(hLib, "SyringeHandshake")))
        {
            Log::WriteLine(__FUNCTION__ ": Calling \"%s\" ...", lib);
            constexpr auto Size = 0x100u;
            std::vector<char> buffer(Size + 1); // one more than we tell the dll

            auto const shInfo = std::make_unique<SyringeHandshakeInfo>();
            shInfo->cbSize = sizeof(SyringeHandshakeInfo);
            shInfo->num_hooks = hooks;
            shInfo->checksum = crc;
            shInfo->exeFilesize = dwExeSize;
            shInfo->exeTimestamp = dwTimeStamp;
            shInfo->exeCRC = dwExeCRC;
            shInfo->cchMessage = static_cast<int>(Size);
            shInfo->Message = buffer.data();

            if (auto const res = func(shInfo.get()); SUCCEEDED(res))
            {
                buffer.back() = 0;
                Log::WriteLine(
                    __FUNCTION__ ": Answers \"%s\" (%X)", buffer.data(), res);
                ret = (res == S_OK);
            }
            else
            {
                // don't use any properties of shInfo.
                Log::WriteLine(__FUNCTION__ ": Failed (%X)", res);
                ret = false;
            }
        }
        else
        {
            // Log::WriteLine(__FUNCTION__ ": Not available.");
        }
    }

    return ret;
}
