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

NTSTATUS H2MapReadOnlyFile(
	_In_ PUNICODE_STRING FileName,
	_In_ ULONG AllocationAttributes,
	_Out_ PVOID *Base,
	_Out_ SIZE_T *Size,
    _Out_opt_ PCWSTR *LastCall
)
{
    NTSTATUS status;
    PCWSTR lastCall;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK isb;

    InitializeObjectAttributes(&objAttr, FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    lastCall = L"NtOpenFile";
    status = NtOpenFile(
        &hFile,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &isb,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    lastCall = L"NtCreateSection";
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        AllocationAttributes,
        hFile
    );

    NtClose(hFile);
    hFile = NULL;

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    PVOID base;
    SIZE_T size;
    base = NULL;
    size = 0;

    lastCall = L"NtMapViewOfSection";
    status = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &base,
        0,
        0,
        NULL,
        &size,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    NtClose(hSection);
    hSection = NULL;

    if (!NT_SUCCESS(status))
        goto CLEANUP;
    
    *Base = base;
    *Size = size;   

CLEANUP:
    if (LastCall)
        *LastCall = lastCall;

    return status;
}

NTSTATUS H2IsImageCompatible(
    _In_ PIMAGE_NT_HEADERS ImageNtHeaders,
    _In_ BOOLEAN TargetIsWoW64
)
{
    switch (ImageNtHeaders->OptionalHeader.Magic)
    {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            if (!TargetIsWoW64)
                return STATUS_INVALID_IMAGE_WIN_32;
            break;

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
#ifdef _WIN64
            if (TargetIsWoW64)
#endif
                return STATUS_INVALID_IMAGE_WIN_64;
            break;
    
        default:
            return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

NTSTATUS H2MapImagesFromData(
    _In_ PVOID Data,
    _In_ SIZE_T DataSize,
    _In_ HANDLE hProcess,
    _Out_ PVOID *LocalImageAddress,
    _Out_ PVOID *RemoteImageAddress,
    _Out_ SIZE_T *ImageSize,
    _Out_opt_ PCWSTR *LastCall
)
{
    NTSTATUS status;
    PCWSTR lastCall;
    HANDLE hSection = NULL;
    PVOID localAddress = NULL;
    PVOID remoteAddress = NULL;

    PIMAGE_NT_HEADERS imageNtHeader;
    
    lastCall = L"RtlImageNtHeaderEx";
    status = RtlImageNtHeaderEx(
        0,
        Data,
        DataSize,
        &imageNtHeader
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Create a section object for holding PE with the image layout
    LARGE_INTEGER imageSize;
    imageSize.QuadPart = imageNtHeader->OptionalHeader.SizeOfImage;

    lastCall = L"NtCreateSection";
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &imageSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Map it locally for writing
    SIZE_T localSize;
    localSize = 0;

    lastCall = L"NtMapViewOfSection (locally)";
    status = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &localAddress,
        0,
        0,
        NULL,
        &localSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Map it remotely for execution
    SIZE_T remoteSize;
    remoteSize = 0;

    lastCall = L"NtMapViewOfSection (remotely)";
    status = NtMapViewOfSection(
        hSection,
        hProcess,
        &remoteAddress,
        0,
        0,
        NULL,
        &remoteSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_WRITECOPY
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Start contructing the image layout; copy and protect the headers
    SIZE_T headersSize;
    ULONG oldProtection;

    headersSize = imageNtHeader->OptionalHeader.SizeOfHeaders;
    memcpy_s(localAddress, localSize, Data, headersSize);
    NtProtectVirtualMemory(hProcess, &remoteAddress, &headersSize, PAGE_READONLY, &oldProtection);

    for (ULONG i = 0; i < imageNtHeader->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader;
        sectionHeader = RtlOffsetToPointer(IMAGE_FIRST_SECTION(imageNtHeader), sizeof(IMAGE_SECTION_HEADER) * i);

        if (sectionHeader->VirtualAddress >= localSize)
            continue;

        // Copy each PE section
        memcpy_s(
            RtlOffsetToPointer(localAddress, sectionHeader->VirtualAddress),
            localSize - sectionHeader->VirtualAddress,
            RtlOffsetToPointer(Data, sectionHeader->PointerToRawData),
            sectionHeader->SizeOfRawData
        );

        // Adjust memory protection according to the characteristics        
        PVOID remoteSectionBase;
        SIZE_T remoteSectionSize;
        ULONG protection;

        remoteSectionBase = RtlOffsetToPointer(remoteAddress, sectionHeader->VirtualAddress);
        remoteSectionSize = sectionHeader->Misc.VirtualSize;

        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
            protection = PAGE_EXECUTE_READWRITE;
        else if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            protection = PAGE_EXECUTE_READ;
        else if (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
            protection = PAGE_READWRITE;
        else
            protection = PAGE_READONLY;

        NtProtectVirtualMemory(hProcess, &remoteSectionBase, &remoteSectionSize, protection, &oldProtection);
    }

    *LocalImageAddress = localAddress;
    *RemoteImageAddress = remoteAddress;
    *ImageSize = localSize;

    status = STATUS_SUCCESS;

CLEANUP:
    if (hSection)
        NtClose(hSection);

    if (!NT_SUCCESS(status) && localAddress)
        NtUnmapViewOfSection(NtCurrentProcess(), localAddress);

    if (!NT_SUCCESS(status) && remoteAddress)
        NtUnmapViewOfSection(hProcess, remoteAddress);

    if (LastCall)
        *LastCall = lastCall;

    return status;
}