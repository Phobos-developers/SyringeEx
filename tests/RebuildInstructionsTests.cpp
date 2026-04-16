#include "SyringeDebugger.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// ---- minimal test harness ----

static int g_total = 0;
static int g_passed = 0;
static int g_failed = 0;

#define TEST_CASE(name) static void test_##name(); \
    struct TestReg_##name { TestReg_##name() { tests().push_back({#name, test_##name}); } } reg_##name; \
    static void test_##name()

struct TestEntry { const char* name; void (*fn)(); };
static std::vector<TestEntry>& tests() { static std::vector<TestEntry> v; return v; }

static void check_impl(bool cond, const char* expr, const char* file, int line)
{
    ++g_total;
    if (cond) {
        ++g_passed;
    } else {
        ++g_failed;
        printf("  FAIL: %s (%s:%d)\n", expr, file, line);
    }
}

#define CHECK(expr) check_impl(!!(expr), #expr, __FILE__, __LINE__)

// ---- Zydis helpers for verification ----

static bool decode_branch_target(const BYTE* code, size_t len, DWORD runtime_addr, DWORD* target)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, code, len, &instr, operands)))
        return false;

    for (ZyanU8 i = 0; i < instr.operand_count_visible; ++i)
    {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            ZyanU64 abs;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[i], runtime_addr, &abs)))
            {
                *target = static_cast<DWORD>(abs);
                return true;
            }
        }
    }
    return false;
}

static ZydisMnemonic decode_mnemonic(const BYTE* code, size_t len)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, code, len, &instr, operands)))
        return ZYDIS_MNEMONIC_INVALID;

    return instr.mnemonic;
}

// ============================================================================
// Test cases
// ============================================================================

// Non-relative instructions should be copied verbatim.
TEST_CASE(non_relative_copied_verbatim)
{
    // add esp, 8 ; test eax, eax
    // 83 C4 08     85 C0
    BYTE bytes[] = { 0x83, 0xC4, 0x08, 0x85, 0xC0 };
    DWORD origAddr = 0x00400000;
    DWORD newAddr  = 0x10000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    CHECK(result.size() == sizeof(bytes));
    CHECK(memcmp(result.data(), bytes, sizeof(bytes)) == 0);
}

// Short JNZ (75 xx) relocated to a far-away address should become near JNZ (0F 85 xx xx xx xx)
// and still target the same absolute address.
TEST_CASE(short_jnz_relocated)
{
    // At 0x005DBA4E: 75 14 => jnz $+0x16 => target = 0x005DBA64
    BYTE bytes[] = { 0x75, 0x14 };
    DWORD origAddr = 0x005DBA4E;
    DWORD newAddr  = 0x10000000; // far away

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    // Should have been re-encoded (likely 6 bytes for near jnz)
    CHECK(result.size() == 6);
    CHECK(decode_mnemonic(result.data(), result.size()) == ZYDIS_MNEMONIC_JNZ);

    DWORD target = 0;
    CHECK(decode_branch_target(result.data(), result.size(), newAddr, &target));
    CHECK(target == 0x005DBA64);
}

// Short JMP (EB xx) relocated far should become near JMP (E9 xx xx xx xx).
TEST_CASE(short_jmp_relocated)
{
    // At 0x00401000: EB 10 => jmp $+0x12 => target = 0x00401012
    BYTE bytes[] = { 0xEB, 0x10 };
    DWORD origAddr = 0x00401000;
    DWORD newAddr  = 0x20000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    CHECK(result.size() == 5);
    CHECK(decode_mnemonic(result.data(), result.size()) == ZYDIS_MNEMONIC_JMP);

    DWORD target = 0;
    CHECK(decode_branch_target(result.data(), result.size(), newAddr, &target));
    CHECK(target == 0x00401012);
}

// Near CALL (E8 xx xx xx xx) relocated should still resolve to the same absolute target.
TEST_CASE(near_call_relocated)
{
    // At 0x00401000: E8 FB 0F 00 00 => call 0x00402000
    BYTE bytes[] = { 0xE8, 0xFB, 0x0F, 0x00, 0x00 };
    DWORD origAddr = 0x00401000;
    DWORD newAddr  = 0x30000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    CHECK(result.size() == 5); // near call stays 5 bytes
    CHECK(decode_mnemonic(result.data(), result.size()) == ZYDIS_MNEMONIC_CALL);

    DWORD target = 0;
    CHECK(decode_branch_target(result.data(), result.size(), newAddr, &target));
    CHECK(target == 0x00402000);
}

// Near JMP (E9 xx xx xx xx) relocated should preserve target.
TEST_CASE(near_jmp_relocated)
{
    // At 0x00401000: E9 FB 0F 00 00 => jmp 0x00402000
    BYTE bytes[] = { 0xE9, 0xFB, 0x0F, 0x00, 0x00 };
    DWORD origAddr = 0x00401000;
    DWORD newAddr  = 0x40000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    CHECK(result.size() == 5);
    CHECK(decode_mnemonic(result.data(), result.size()) == ZYDIS_MNEMONIC_JMP);

    DWORD target = 0;
    CHECK(decode_branch_target(result.data(), result.size(), newAddr, &target));
    CHECK(target == 0x00402000);
}

// Mixed: non-relative instructions + short jnz (the real-world scenario from the bug report).
// 83 C4 08  85 C0  75 14  at 0x005DBA49
TEST_CASE(mixed_instructions_with_jnz)
{
    BYTE bytes[] = { 0x83, 0xC4, 0x08, 0x85, 0xC0, 0x75, 0x14 };
    DWORD origAddr = 0x005DBA49;
    DWORD newAddr  = 0x10000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    // First 5 bytes (add esp,8 + test eax,eax) should be verbatim.
    CHECK(result.size() >= 5);
    CHECK(memcmp(result.data(), bytes, 5) == 0);

    // The jnz should have been re-encoded. Original: 75 14 at offset 5 from origAddr
    // => src = 0x005DBA4E, target = srcAddr + 2 + 0x14 = 0x005DBA64
    BYTE const* jnz_ptr = result.data() + 5;
    size_t jnz_len = result.size() - 5;
    DWORD jnz_new_addr = newAddr + 5;

    CHECK(decode_mnemonic(jnz_ptr, jnz_len) == ZYDIS_MNEMONIC_JNZ);

    DWORD target = 0;
    CHECK(decode_branch_target(jnz_ptr, jnz_len, jnz_new_addr, &target));
    CHECK(target == 0x005DBA64);
}

// Short JNZ that stays short when addresses are close enough.
TEST_CASE(short_jnz_stays_short_when_close)
{
    // 75 14 at 0x00401000, relocated to 0x00401100 (only 256 bytes away)
    BYTE bytes[] = { 0x75, 0x14 };
    DWORD origAddr = 0x00401000;
    DWORD newAddr  = 0x00401100;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    CHECK(decode_mnemonic(result.data(), result.size()) == ZYDIS_MNEMONIC_JNZ);

    // Target should still be 0x00401016
    DWORD target = 0;
    CHECK(decode_branch_target(result.data(), result.size(), newAddr, &target));
    CHECK(target == 0x00401016);
}

// Near conditional JNZ (0F 85 xx xx xx xx) should preserve target when relocated.
TEST_CASE(near_jnz_relocated)
{
    // At 0x00401000: 0F 85 FA 0F 00 00 => jnz 0x00402000
    BYTE bytes[] = { 0x0F, 0x85, 0xFA, 0x0F, 0x00, 0x00 };
    DWORD origAddr = 0x00401000;
    DWORD newAddr  = 0x50000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    CHECK(result.size() == 6);
    CHECK(decode_mnemonic(result.data(), result.size()) == ZYDIS_MNEMONIC_JNZ);

    DWORD target = 0;
    CHECK(decode_branch_target(result.data(), result.size(), newAddr, &target));
    CHECK(target == 0x00402000);
}

// Multiple relative instructions in sequence.
TEST_CASE(multiple_relative_instructions)
{
    // E8 FB 0F 00 00  => call 0x00402000  (at 0x00401000)
    // 75 08           => jnz  $+0x0A     (at 0x00401005) => target 0x0040100F
    // E9 F4 EF FF FF  => jmp  0x00400000  (at 0x00401007)
    BYTE bytes[] = {
        0xE8, 0xFB, 0x0F, 0x00, 0x00,
        0x75, 0x08,
        0xE9, 0xF4, 0xEF, 0xFF, 0xFF
    };
    DWORD origAddr = 0x00401000;
    DWORD newAddr  = 0x60000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    // Decode each rebuilt instruction and verify targets.
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    DWORD expected_targets[] = { 0x00402000, 0x0040100F, 0x00400000 };
    ZydisMnemonic expected_mnemonics[] = { ZYDIS_MNEMONIC_CALL, ZYDIS_MNEMONIC_JNZ, ZYDIS_MNEMONIC_JMP };

    size_t off = 0;
    for (int i = 0; i < 3 && off < result.size(); ++i)
    {
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (ZYAN_FAILED(ZydisDecoderDecodeFull(
                &decoder, result.data() + off, result.size() - off, &instr, operands)))
        {
            CHECK(false); // decode failure
            break;
        }

        CHECK(instr.mnemonic == expected_mnemonics[i]);

        for (ZyanU8 j = 0; j < instr.operand_count_visible; ++j)
        {
            if (operands[j].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                ZyanU64 abs;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                        &instr, &operands[j], newAddr + off, &abs)))
                {
                    CHECK(static_cast<DWORD>(abs) == expected_targets[i]);
                }
            }
        }

        off += instr.length;
    }
}

// Zero-length input should produce empty output.
TEST_CASE(empty_input)
{
    BYTE dummy = 0;
    auto result = SyringeDebugger::RebuildInstructions(&dummy, 0, 0x00400000, 0x10000000);
    CHECK(result.empty());
}

// Single NOP instruction (non-relative) should be copied verbatim.
TEST_CASE(single_nop)
{
    BYTE bytes[] = { 0x90 };
    DWORD origAddr = 0x00400000;
    DWORD newAddr  = 0x10000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    CHECK(result.size() == 1);
    CHECK(result[0] == 0x90);
}

// Short backward JMP (negative displacement).
TEST_CASE(short_backward_jmp)
{
    // At 0x00401010: EB F0 => jmp $-14 => target = 0x00401002
    BYTE bytes[] = { 0xEB, 0xF0 };
    DWORD origAddr = 0x00401010;
    DWORD newAddr  = 0x70000000;

    auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

    CHECK(decode_mnemonic(result.data(), result.size()) == ZYDIS_MNEMONIC_JMP);

    DWORD target = 0;
    CHECK(decode_branch_target(result.data(), result.size(), newAddr, &target));
    CHECK(target == 0x00401002);
}

// All Jcc short forms should work.
TEST_CASE(various_short_jcc)
{
    struct JccTest {
        BYTE opcode;
        ZydisMnemonic mnemonic;
    };

    JccTest jccs[] = {
        { 0x74, ZYDIS_MNEMONIC_JZ },
        { 0x75, ZYDIS_MNEMONIC_JNZ },
        { 0x72, ZYDIS_MNEMONIC_JB },
        { 0x73, ZYDIS_MNEMONIC_JNB },
        { 0x76, ZYDIS_MNEMONIC_JBE },
        { 0x77, ZYDIS_MNEMONIC_JNBE },
        { 0x7C, ZYDIS_MNEMONIC_JL },
        { 0x7D, ZYDIS_MNEMONIC_JNL },
        { 0x7E, ZYDIS_MNEMONIC_JLE },
        { 0x7F, ZYDIS_MNEMONIC_JNLE },
    };

    DWORD origAddr = 0x00401000;
    DWORD newAddr  = 0x20000000;

    for (auto const& jcc : jccs)
    {
        BYTE bytes[] = { jcc.opcode, 0x20 }; // jcc $+0x22 => target = 0x00401022

        auto result = SyringeDebugger::RebuildInstructions(bytes, sizeof(bytes), origAddr, newAddr);

        CHECK(decode_mnemonic(result.data(), result.size()) == jcc.mnemonic);

        DWORD target = 0;
        CHECK(decode_branch_target(result.data(), result.size(), newAddr, &target));
        CHECK(target == 0x00401022);
    }
}

// ---- entry point ----

int main()
{
    printf("Running RebuildInstructions tests...\n\n");

    for (auto const& t : tests())
    {
        printf("[%s]\n", t.name);
        t.fn();
    }

    printf("\n%d checks, %d passed, %d failed\n", g_total, g_passed, g_failed);
    return g_failed ? 1 : 0;
}
