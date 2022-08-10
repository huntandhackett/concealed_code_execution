/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "mapped_images.h"
#include <wchar.h>

FORCEINLINE
VOID H2PrintStatus(
    _In_ NTSTATUS Status
)
{
    switch (Status)
    {
        case STATUS_FILE_DELETED:
            wprintf_s(L"Error: STATUS_FILE_DELETED\r\n");
            break;

        case STATUS_INVALID_ADDRESS:
            wprintf_s(L"Error: STATUS_INVALID_ADDRESS\r\n");
            break;

        case STATUS_TRANSACTION_NOT_ACTIVE:
            wprintf_s(L"Error: STATUS_TRANSACTION_NOT_ACTIVE\r\n");
            break;

        default:
            wprintf_s(L"Error: 0x%0.8X\r\n", Status);
    }
}

// Scan process's memory and print named of mapped images
NTSTATUS H2PrintMappedImagesProcessID(
	_In_ HANDLE ProcessID
)
{
    NTSTATUS status;
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;

    /* Open the target process for inspection */

    clientId.UniqueProcess = ProcessID;
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = NtOpenProcess(
        &hProcess,
        PROCESS_QUERY_LIMITED_INFORMATION,
        &objAttr,
        &clientId
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot open the target process: %X\r\n", status);
        return status;
    }

    /* Determine if the process runs under WoW64 */

    PPEB32 wow64Peb;

    status = NtQueryInformationProcess(
        hProcess,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        NtClose(hProcess);
        wprintf_s(L"Cannot determine if the process is running under WoW64: %X\r\n", status);
        return status;
    }

#ifndef _WIN64
    if (!!NtCurrentTeb()->WowTebOffset ^ !!wow64Peb)
    {
        NtClose(hProcess);
        wprintf_s(L"Unable to query. Please use the 64-bit version of the tool.\r\n");
        return STATUS_WOW_ASSERTION;
    }
#endif

    /* Iterate over memory regions of the process */

    MEMORY_BASIC_INFORMATION memoryInfo;
    ULONG count = 0;

    for (
        PVOID address = NULL;
        NT_SUCCESS(NtQueryVirtualMemory(
            hProcess,
            address,
            MemoryBasicInformation,
            &memoryInfo,
            sizeof(memoryInfo),
            NULL
        ));
        address = RtlOffsetToPointer(address, memoryInfo.RegionSize)
        )
    {
        // Skip regions smaller than entire allocations
        if (memoryInfo.AllocationBase != memoryInfo.BaseAddress)
            continue;

        // Skip non-images
        if (!(memoryInfo.Type & MEM_IMAGE))
            continue;
        
        // Skip non-executable images (aka. SEC_IMAGE_NO_EXECUTE)
        if (memoryInfo.AllocationProtect & (PAGE_READONLY | PAGE_WRITECOPY))
            continue;

        count++;
        wprintf_s(L"[0x%0.12zX]: ", (ULONG_PTR)(memoryInfo.AllocationBase));

        NTSTATUS status;
        PUNICODE_STRING nativeFileName;
        PUNICODE_STRING dosFileName;

        // Lookup the filename
        status = H2QueryFileAtAddress(
            hProcess,
            memoryInfo.AllocationBase,
            &nativeFileName
        );

        if (NT_SUCCESS(status))
        {
            // Prefer Win32 file names when available
            status = H2NativeNameToDosName(
                nativeFileName,
                &dosFileName
            );

            wprintf_s(L"%wZ\r\n", NT_SUCCESS(status) ? dosFileName : nativeFileName);
        }
        else
        {
            H2PrintStatus(status);
        }
    }

    wprintf_s(L"Found %u executable images.\r\n", count);

    NtClose(hProcess);
    return STATUS_SUCCESS;
}