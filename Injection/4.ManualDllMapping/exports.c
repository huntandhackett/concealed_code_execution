/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "manual_mapping.h"
#include <search.h>
#include <stdio.h>

// Callback for binary search of exports
int __cdecl NameComparer(void* context, const void* key, const void* datum)
{
    return strcmp((PCSTR)key, RtlOffsetToPointer(context, *(PULONG)datum));
}

NTSTATUS H2FindExportedRoutine(
    _In_ PVOID ImageAddress,
    _In_ ULONG64 ImageSize,
    _In_ PCSTR RoutineName,
    _Out_ PULONG RoutineRVA,
    _Out_opt_ PULONG pEntrypointRVA
)
{
    NTSTATUS status;
    PIMAGE_NT_HEADERS imageNtHeader;
    ULONG exportDirectoryRva;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    PULONG names;
    PULONG functions;
    PUSHORT nameOrdinals;
    PULONG routineEntry;

    status = RtlImageNtHeaderEx(
        0,
        ImageAddress,
        ImageSize,
        &imageNtHeader
    );

    if (!NT_SUCCESS(status))
        return status;

    exportDirectoryRva = HEADER_FIELD(imageNtHeader, DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
    exportDirectory = RtlOffsetToPointer(ImageAddress, exportDirectoryRva);
    names = RtlOffsetToPointer(ImageAddress, exportDirectory->AddressOfNames);
    functions = RtlOffsetToPointer(ImageAddress, exportDirectory->AddressOfFunctions);
    nameOrdinals = RtlOffsetToPointer(ImageAddress, exportDirectory->AddressOfNameOrdinals);

    // Exported names are sorted; use binary search
    routineEntry = bsearch_s(
        RoutineName,
        names,
        exportDirectory->NumberOfNames,
        sizeof(ULONG),
        NameComparer,
        ImageAddress
    );

    if (!routineEntry)
        return STATUS_ENTRYPOINT_NOT_FOUND;

    *RoutineRVA = functions[nameOrdinals[routineEntry - names]];

    if (pEntrypointRVA)
        *pEntrypointRVA = imageNtHeader->OptionalHeader.AddressOfEntryPoint;

    return STATUS_SUCCESS;
}

NTSTATUS H2FindKnownDllExport(
    _In_ PCWSTR KnownDllSectionName,
    _In_ PCSTR FunctionName,
    _Out_ PVOID *FunctionAddress,
    _Out_opt_ PCWSTR *LastCall
)
{
    NTSTATUS status;
    PCWSTR lastCall;
    UNICODE_STRING sectionNameStr;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hSection = NULL;
    PVOID mappingBase = NULL;
    SIZE_T mappingSize = 0;

    // Open the section by name
    RtlInitUnicodeString(&sectionNameStr, KnownDllSectionName);
    InitializeObjectAttributes(&objAttr, &sectionNameStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    lastCall = L"NtOpenSection";
    status = NtOpenSection(
        &hSection,
        SECTION_MAP_READ | SECTION_QUERY,
        &objAttr
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Map the image for parsing
    lastCall = L"NtMapViewOfSection";
    status = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &mappingBase,
        0,
        0,
        NULL,
        &mappingSize,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Parse the exports and find the function
    ULONG functionRVA;
    ULONG entrypointRVA;

    lastCall = L"Export parsing";
    status = H2FindExportedRoutine(
        mappingBase,
        mappingSize,
        FunctionName,
        &functionRVA,
        &entrypointRVA
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Determine image's system-wide address
    SECTION_IMAGE_INFORMATION sectionInfo;

    lastCall = L"NtQuerySection [SectionImageInformation]";
    status = NtQuerySection(
        hSection,
        SectionImageInformation,
        &sectionInfo,
        sizeof(sectionInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    *FunctionAddress = (PVOID)((ULONG_PTR)sectionInfo.TransferAddress - entrypointRVA + functionRVA);

CLEANUP:
    if (hSection)
        NtClose(hSection);
    
    if (mappingBase)
        NtUnmapViewOfSection(NtCurrentProcess(), mappingBase);

    if (LastCall)
        *LastCall = lastCall;

    return status;
}

NTSTATUS H2LookupFileAtAddress(
    _In_ HANDLE hProcess,
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING *FullFileName,
    _Out_ PANSI_STRING *ShortFileName
)
{
    NTSTATUS status;
    PUNICODE_STRING fullFilename = NULL;
    PANSI_STRING shortFilename = NULL;

    SIZE_T fullFilenameSize;
    fullFilenameSize = RtlGetLongestNtPathLength() * sizeof(WCHAR);

    do
    {
        fullFilename = RtlAllocateHeap(
            RtlGetCurrentPeb()->ProcessHeap,
            0,
            fullFilenameSize
        );

        if (!fullFilename)
            return STATUS_NO_MEMORY;

        // Query the full filename
        status = NtQueryVirtualMemory(
            hProcess,
            Address,
            MemoryMappedFilenameInformation,
            fullFilename,
            fullFilenameSize,
            &fullFilenameSize
        );

        if (!NT_SUCCESS(status))
        {
            RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, fullFilename);
            fullFilename = NULL;
        }
    }
    while (status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(status))
        return status;

    // Extract the name of the file without the path
    UNICODE_STRING namePart;

    namePart.Length = 0;
    namePart.Buffer = (PWCH)RtlOffsetToPointer(fullFilename->Buffer, fullFilename->Length);

    while (namePart.Buffer > fullFilename->Buffer && namePart.Buffer[-1] != L'\\')
    {
        namePart.Length += sizeof(WCHAR);
        namePart.Buffer--;
    }

    namePart.MaximumLength = namePart.Length;

    // Allocate space for the short ANSI name
    shortFilename = RtlAllocateHeap(
        RtlGetCurrentPeb()->ProcessHeap,
        0,
        sizeof(ANSI_STRING) + namePart.MaximumLength / sizeof(WCHAR) + sizeof(ANSI_NULL)
    );

    if (!shortFilename)
    {
        status = STATUS_NO_MEMORY;
        goto CLEANUP;
    }

    // Convert the short name to ANSI format
    shortFilename->Buffer = RtlOffsetToPointer(shortFilename, sizeof(ANSI_STRING));
    shortFilename->Length = 0;
    shortFilename->MaximumLength = namePart.MaximumLength / sizeof(WCHAR) + sizeof(ANSI_NULL);

    status = RtlUnicodeStringToAnsiString(shortFilename, &namePart, FALSE);

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    *FullFileName = fullFilename;
    *ShortFileName = shortFilename;
    return STATUS_SUCCESS;

CLEANUP:    
    if (fullFilename)
        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, fullFilename);

    if (shortFilename)
        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, shortFilename);

    return status;
}

NTSTATUS H2ResoleImports(
    _In_ HANDLE hProcess,
    _In_ PVOID LocalAddress,
    _In_ SIZE_T ImageSize
)
{
    NTSTATUS status;
    PIMAGE_NT_HEADERS imageNtHeader;

    status = RtlImageNtHeaderEx(
        0,
        LocalAddress,
        ImageSize,
        &imageNtHeader
    );

    if (!NT_SUCCESS(status))
        return status;

    BOOLEAN is64Bit = imageNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    ULONG importDirectoryRva = HEADER_FIELD(imageNtHeader,
            DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]).VirtualAddress;

    // No imports to resolve
    if (!importDirectoryRva)
        return STATUS_SUCCESS;
    
    // Scan the address space for loaded images
    MEMORY_BASIC_INFORMATION basicInfo;

    for (
        PVOID address = NULL;
        NT_SUCCESS(NtQueryVirtualMemory(
            hProcess,
            address,
            MemoryBasicInformation,
            &basicInfo,
            sizeof(basicInfo),
            NULL
        ));
        address = RtlOffsetToPointer(address, basicInfo.RegionSize)
        )
    {
        // Skip regions smaller than allocations
        if (basicInfo.AllocationBase != basicInfo.BaseAddress)
            continue;

        // Skip non-images
        if (!(basicInfo.Type & MEM_IMAGE))
            continue;

        // Lookup the file name
        PUNICODE_STRING fullName;
        PANSI_STRING shortName;
        status = H2LookupFileAtAddress(hProcess, basicInfo.AllocationBase, &fullName, &shortName);

        if (!NT_SUCCESS(status))
            continue;

        // Check if there are any imports from this file
        for (
            PIMAGE_IMPORT_DESCRIPTOR importDescriptor = RtlOffsetToPointer(LocalAddress, importDirectoryRva);
            importDescriptor->Name;
            importDescriptor++
            )
        {
            ANSI_STRING dllName;
            RtlInitAnsiString(&dllName, RtlOffsetToPointer(LocalAddress, importDescriptor->Name));

            BOOLEAN nameMatches;
            nameMatches = RtlEqualString(&dllName, shortName, TRUE);

            if (!nameMatches)
                continue;

            // Map the file for parsing
            PVOID dllBase;
            SIZE_T dllSize;

            status = H2MapReadOnlyFile(fullName, SEC_IMAGE_NO_EXECUTE, &dllBase, &dllSize, NULL);

            if (!NT_SUCCESS(status))
                continue;

            PVOID iat = RtlOffsetToPointer(LocalAddress, importDescriptor->FirstThunk);

            // Go through all functions that we import from the module
            for (
                PVOID unboundIAT = RtlOffsetToPointer(LocalAddress, importDescriptor->OriginalFirstThunk);
                is64Bit ? *(PULONG64)unboundIAT : *(PULONG)unboundIAT;
                is64Bit ? ((PULONG64)unboundIAT)++ && ((PULONG64)iat)++ : ((PULONG)unboundIAT)++ && ((PULONG)iat)++
            )
            {
                if (is64Bit ? *(PULONG64)unboundIAT & (1ui64 << 63) : *(PULONG)unboundIAT & (1u << 31))
                {
                    // TODO: Import by ordinal
                }
                else
                {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME functionImport;
                    ULONG functionRVA;

                    functionImport = RtlOffsetToPointer(LocalAddress, *(PULONG)unboundIAT);

                    status = H2FindExportedRoutine(dllBase, dllSize, &functionImport->Name[0], &functionRVA, NULL);

                    if (!NT_SUCCESS(status))
                        continue;

                    PVOID functionAddress;
                    functionAddress = RtlOffsetToPointer(basicInfo.AllocationBase, functionRVA);

                    if (is64Bit)
                        *(PULONG64)iat = (ULONG64)functionAddress;
                    else
                        *(PULONG)iat = (ULONG)(ULONG_PTR)functionAddress;
                }
            }

            NtUnmapViewOfSection(NtCurrentProcess(), dllBase);
        }

        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, fullName);
        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, shortName);
    }

    return STATUS_SUCCESS;
}

