/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "process_identity.h"

// Query a name of a memory mapped file at a specific address
NTSTATUS H2QueryFileAtAddress(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING *FileName
)
{
    NTSTATUS status;
    PUNICODE_STRING buffer;
    SIZE_T bufferSize = RtlGetLongestNtPathLength() * sizeof(WCHAR);

    do
    {
        status = H2Allocate(bufferSize, &buffer, 0);

        if (!NT_SUCCESS(status))
            break;

        status = NtQueryVirtualMemory(
            Process,
            Address,
            MemoryMappedFilenameInformation,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (NT_SUCCESS(status))
        {
            *FileName = buffer;
            break;
        }
        else
        {
            H2Free(buffer);
        }

    } while (status == STATUS_BUFFER_OVERFLOW);

    return status;
}

// Query and print the name of a file mapped at a specific address
VOID H2PrintFileAtAddress(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _In_opt_ PCWSTR Comment
)
{
    NTSTATUS status;
    PUNICODE_STRING buffer;

    status = H2QueryFileAtAddress(Process, Address, &buffer);

    if (Comment)
        wprintf_s(L"%s:\r\n  ", Comment);

    if (NT_SUCCESS(status))
    {
        wprintf_s(L"%wZ\r\n\r\n", buffer);
        H2Free(buffer);
    }
    else
    {
        H2PrintStatus(status);
    }
}

// Print the file used as the image base of a process
NTSTATUS H2PrintImageBaseFile(
	_In_ HANDLE Process
)
{
	NTSTATUS status;
    PROCESS_BASIC_INFORMATION basicInfo;
    PPEB32 wow64Peb;

    // Determine native PEB location
    status = NtQueryInformationProcess(
        Process,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot determine native PEB location: 0x%X\r\n", status);
        return status;
    }

    // Read the ImageBaseAddress field from PEB
    PVOID imageBase;

    status = NtReadVirtualMemory(
        Process,
        &basicInfo.PebBaseAddress->ImageBaseAddress,
        &imageBase,
        sizeof(imageBase),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read the native image base: 0x%X\r\n", status);
        return status;
    }

    // Query and print the file mapped at the base address
    H2PrintFileAtAddress(Process, imageBase, L"Image mapped at base");

    // Query WoW64 PEB location
    status = NtQueryInformationProcess(
        Process,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot determine if the target runs under WoW64: 0x%X\r\n", status);
        return status;
    }

    if (wow64Peb)
    {
        // Read the ImageBaseAddress field from WoW64 PEB
        WOW64_POINTER(PVOID) imageBase32;

        status = NtReadVirtualMemory(
            Process,
            &wow64Peb->ImageBaseAddress,
            &imageBase32,
            sizeof(imageBase32),
            NULL
        );

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Cannot read the native image base: 0x%X\r\n", status);
            return status;
        }

        if ((ULONG_PTR)imageBase32 != (ULONG_PTR)imageBase)
            H2PrintFileAtAddress(Process, (PVOID)(ULONG_PTR)imageBase32, L"Image mapped at base (WoW64)");
    }

    return status;
}
