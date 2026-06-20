#include "PortableExecutable.h"

#include "Log.h"

#include <algorithm>
#include <cassert>

#include <share.h>

// address without the image base!
DWORD PortableExecutable::VirtualToRaw(DWORD const dwAddress) const noexcept
{
    for (auto const& uSection : vecPESections)
    {
        auto const dwDifference = dwAddress - uSection.VirtualAddress;

        if (dwDifference < uSection.SizeOfRawData)
        {
            return uSection.PointerToRawData + dwDifference;
        }
    }

    return 0;
}

bool PortableExecutable::ReadFile()
{
    auto const pFile = this->Handle.get();

    // dos header
    fseek(pFile, 0, SEEK_SET);
    fread(&uDOSHeader, sizeof(IMAGE_DOS_HEADER), 1, pFile);
    if (uDOSHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    // pe header
    fseek(pFile, uDOSHeader.e_lfanew, SEEK_SET);
    fread(&uPEHeader, sizeof(IMAGE_NT_HEADERS), 1, pFile);
    if (uPEHeader.Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    // sections
    vecPESections.resize(uPEHeader.FileHeader.NumberOfSections);
    fread(&vecPESections[0], sizeof(IMAGE_SECTION_HEADER), vecPESections.size(), pFile);

    // imports
    auto const& Imports = uPEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (Imports.Size)
    {
        fseek(pFile, static_cast<long>(VirtualToRaw(Imports.VirtualAddress)), SEEK_SET);

        for (;;)
        {
            IMAGE_IMPORT_DESCRIPTOR import_desc;
            fread(&import_desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pFile);

            if (!import_desc.Characteristics)
            {
                break;
            }

            vecImports.emplace_back().uDesc = import_desc;
        }
    }

    for (auto& current_import : vecImports)
    {
        constexpr auto Size = 0x100;
        char name_buf[Size];
        fseek(pFile, static_cast<long>(VirtualToRaw(current_import.uDesc.Name)), SEEK_SET);
        fgets(name_buf, Size, pFile);

        current_import.Name = name_buf;

        // thunks
        fseek(pFile, static_cast<long>(VirtualToRaw(current_import.uDesc.FirstThunk)), SEEK_SET);

        for (;;)
        {
            IMAGE_THUNK_DATA thunk_data;
            fread(&thunk_data, sizeof(IMAGE_THUNK_DATA), 1, pFile);

            if (!thunk_data.u1.AddressOfData)
            {
                break;
            }

            current_import.vecThunkData.emplace_back().uThunkData = thunk_data;
        }

        auto thunk_addr = reinterpret_cast<IMAGE_THUNK_DATA*>(current_import.uDesc.FirstThunk);
        for (auto& thunk : current_import.vecThunkData)
        {
            thunk.Address = reinterpret_cast<DWORD>(thunk_addr++);
            thunk.bIsOrdinal = IMAGE_SNAP_BY_ORDINAL(thunk.uThunkData.u1.Ordinal);

            if (thunk.bIsOrdinal)
            {
                thunk.Ordinal = IMAGE_ORDINAL(thunk.uThunkData.u1.Ordinal);
            }
            else
            {
                fseek(pFile, static_cast<long>(VirtualToRaw(thunk.uThunkData.u1.AddressOfData)), SEEK_SET);
                fread(&thunk.wWord, 2, 1, pFile);
                fgets(name_buf, Size, pFile);
                thunk.Name = name_buf;
            }
        }
    }

    return true;
}

bool PortableExecutable::ReadBytes(
    DWORD const dwRawAddress, size_t const Size, void* const Dest) const noexcept
{
    auto const pFile = this->Handle.get();

    if (!fseek(pFile, static_cast<long>(dwRawAddress), SEEK_SET))
    {
        return (fread(Dest, Size, 1, pFile) == 1);
    }

    return false;
}

bool PortableExecutable::ReadCString(
    DWORD const dwRawAddress, std::string& Result) const
{
    auto const pFile = this->Handle.get();

    if (!fseek(pFile, static_cast<long>(dwRawAddress), SEEK_SET))
    {
        constexpr size_t sz = 0x100;
        char tmpBuf[sz];

        tmpBuf[0] = 0;
        if (fread(tmpBuf, 1, sz, pFile) == sz)
        {
            tmpBuf[sz - 1] = 0;
            Result.assign(tmpBuf);
            return true;
        }
    }

    return false;
}

IMAGE_SECTION_HEADER const* PortableExecutable::FindSection(
    std::string_view const name) const noexcept
{
    assert(name.size() <= IMAGE_SIZEOF_SHORT_NAME);
    char buffer[IMAGE_SIZEOF_SHORT_NAME] = {};
    std::memcpy(buffer, name.data(), name.size());

    auto const found = std::find_if(
        vecPESections.cbegin(), vecPESections.cend(),
        [&buffer](auto const& section)
        {
            return !memcmp(section.Name, buffer, std::size(buffer));
        });

    if (found == vecPESections.cend())
    {
        return nullptr;
    }
    else
    {
        return &(*found);
    }
}


std::unordered_map<std::string, DWORD> PortableExecutable::GetExportSymbols() const noexcept
{
    std::unordered_map<std::string, DWORD> exportSymbols;

    IMAGE_DATA_DIRECTORY const& exportTable = uPEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportTable.Size == 0) {
        return exportSymbols;
    }
    DWORD rawExportAddress = VirtualToRaw(exportTable.VirtualAddress);
    if (rawExportAddress == 0) {
        return exportSymbols;
    }
    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadBytes(rawExportAddress, sizeof(IMAGE_EXPORT_DIRECTORY), &exportDir)) {
        return exportSymbols;
    }
    std::string moduleName;
    if (!ReadCString(VirtualToRaw(exportDir.Name), moduleName))
    {
        moduleName = "";
    }

    std::vector<DWORD> addressOfFunctions;
    size_t funcCount = exportDir.NumberOfFunctions;
    addressOfFunctions.resize(funcCount);
    if (!ReadBytes(VirtualToRaw(exportDir.AddressOfFunctions), sizeof(DWORD) * funcCount, addressOfFunctions.data())) {
        return exportSymbols;
    }

    std::vector<DWORD> addressOfNames;
    size_t nameCount = exportDir.NumberOfNames;
    addressOfNames.resize(nameCount);
    if (!ReadBytes(VirtualToRaw(exportDir.AddressOfNames), sizeof(DWORD) * nameCount, addressOfNames.data())) {
        return exportSymbols;
    }

    std::vector<WORD> addressOfNameOrdinals;
    addressOfNameOrdinals.resize(nameCount);
    if (!ReadBytes(VirtualToRaw(exportDir.AddressOfNameOrdinals), sizeof(WORD) * nameCount, addressOfNameOrdinals.data())) {
        return exportSymbols;
    }

    for (size_t i = 0; i < nameCount; ++i) {
        DWORD nameRVA = addressOfNames[i];
        DWORD rawNameAddress = VirtualToRaw(nameRVA);
        if (rawNameAddress == 0) {
            continue;
        }

        std::string nameANSI;
        if (!ReadCString(rawNameAddress, nameANSI)) {
            continue;
        }

        WORD ordinal = addressOfNameOrdinals[i];
        if (ordinal >= funcCount) {
            continue; // 无效序号
        }

        DWORD functionRVA = addressOfFunctions[ordinal];
        exportSymbols[nameANSI] = functionRVA;
    }

    return exportSymbols;
}