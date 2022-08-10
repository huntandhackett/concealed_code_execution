/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "loaded_modules.h"
#include <wchar.h>

// Traverse the list of modules in the native PEB
NTSTATUS H2EnumerateModulesProcessNative(
    _In_ HANDLE Process,
    _In_ PPEB Peb
)
{
    NTSTATUS status;

    wprintf_s(L"------ Modules from the %s-bit PEB ------\r\n\r\n", BITNESS);

    /* Read the address of the loader data */

    PPEB_LDR_DATA pLdrData;
    
    status = NtReadVirtualMemory(
        Process,
        &Peb->Ldr,
        &pLdrData,
        sizeof(pLdrData),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read the address of the loader data: %X\r\n", status);
        return status;
    }

    /* Read the loader data */

    PEB_LDR_DATA ldrData;

    status = NtReadVirtualMemory(
        Process,
        pLdrData,
        &ldrData,
        sizeof(ldrData),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read the loader data: %X\r\n", status);
        return status;
    }

    if (!ldrData.Initialized)
    {
        wprintf_s(L"The loader data is not initialized; no modules found.\r\n");
        return STATUS_NOT_FOUND;
    }

    /* Determine which fields we want to read */

    // Include load reason on Windows 8+
    ULONG bytesToRead =
        (RtlGetCurrentPeb()->OSMajorVersion > 6 ||
            (RtlGetCurrentPeb()->OSMajorVersion == 6 &&
            RtlGetCurrentPeb()->OSMinorVersion >= 2)) ? 
        FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, ImplicitPathOptions) :
        FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseNameHashValue);

    /* Traverse the in-order module list */

    ULONG index = 0;
    PLIST_ENTRY start = &pLdrData->InLoadOrderModuleList;
    PLIST_ENTRY current = ldrData.InLoadOrderModuleList.Flink;

    while (current != start)
    {
        // Read the module entry
        LDR_DATA_TABLE_ENTRY entry;
        entry.LoadReason = LoadReasonUnknown;

        status = NtReadVirtualMemory(
            Process,
            CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
            &entry,
            bytesToRead,
            NULL
        );

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Cannot read the module entry: %X\r\n", status);
            return status;
        }

        // Print it
        H2PrintProcessModule(
            Process,
            index,
            entry.BaseDllName.Buffer,
            entry.BaseDllName.Length,
            entry.FullDllName.Buffer,
            entry.FullDllName.Length,
            (ULONG_PTR)entry.DllBase,
            entry.SizeOfImage,
            entry.TimeDateStamp,
            entry.LoadTime.QuadPart,
            entry.LoadReason
        );
        
        // Go to the next entry
        current = entry.InLoadOrderLinks.Flink;
        index++;
    }

    wprintf_s(L"Found %u modules (%s-bit).\r\n\r\n", index, BITNESS);

    return STATUS_SUCCESS;
}

#ifdef _WIN64
NTSTATUS H2EnumerateModulesProcessWoW64(
    _In_ HANDLE Process,
    _In_ PPEB32 Peb32
)
{
    NTSTATUS status;

    wprintf_s(L"------ Modules from the 32-bit (WoW64) PEB ------\r\n\r\n");

    /* Read the address of the 32-bit loader data */

    PPEB_LDR_DATA32 pLdrData = NULL;

    status = NtReadVirtualMemory(
        Process,
        &Peb32->Ldr,
        &pLdrData,
        sizeof(WOW64_POINTER(PPEB_LDR_DATA32)),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read the address of the loader data: %X\r\n", status);
        return status;
    }

    /* Read the 32-loader data */

    PEB_LDR_DATA32 ldrData;

    status = NtReadVirtualMemory(
        Process,
        pLdrData,
        &ldrData,
        sizeof(ldrData),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read the loader data: %X\r\n", status);
        return status;
    }

    if (!ldrData.Initialized)
    {
        wprintf_s(L"The loader data is not initialized; no modules found.\r\n");
        return STATUS_NOT_FOUND;
    }

    /* Determine which fields we want to read */

    // Include load reason on Windows 8+
    ULONG bytesToRead =
        (RtlGetCurrentPeb()->OSMajorVersion > 6 ||
            (RtlGetCurrentPeb()->OSMajorVersion == 6 &&
                RtlGetCurrentPeb()->OSMinorVersion >= 2)) ?
        FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32, ImplicitPathOptions) :
        FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32, BaseNameHashValue);

    /* Traverse the in-order module list */

    ULONG index = 0;
    PLIST_ENTRY32 start = &pLdrData->InLoadOrderModuleList;
    PLIST_ENTRY32 current = (PLIST_ENTRY32)(ULONG_PTR)ldrData.InLoadOrderModuleList.Flink;

    while (current != start)
    {
        // Read the module entry
        LDR_DATA_TABLE_ENTRY32 entry;
        entry.LoadReason = LoadReasonUnknown;

        status = NtReadVirtualMemory(
            Process,
            CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks),
            &entry,
            bytesToRead,
            NULL
        );

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Cannot read the module entry: %X\r\n", status);
            return status;
        }

        // Print it
        H2PrintProcessModule(
            Process,
            index,
            (PCWSTR)(ULONG_PTR)entry.BaseDllName.Buffer,
            entry.BaseDllName.Length,
            (PCWSTR)(ULONG_PTR)entry.FullDllName.Buffer,
            entry.FullDllName.Length,
            (ULONG_PTR)entry.DllBase,
            entry.SizeOfImage,
            entry.TimeDateStamp,
            entry.LoadTime.QuadPart,
            entry.LoadReason
        );

        // Go to the next entry
        current = (PLIST_ENTRY32)(ULONG_PTR)entry.InLoadOrderLinks.Flink;
        index++;
    }

    wprintf_s(L"Found %u modules (32-bit).\r\n\r\n", index);

    return STATUS_SUCCESS;
}
#endif // _WIN64

// Print the list of modules from a live process
NTSTATUS H2EnumerateModulesProcess(
    _In_ ULONG_PTR PID
)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;

    /* Open the target process */

    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;

    clientId.UniqueProcess = (HANDLE)PID;
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = NtOpenProcess(
        &hProcess,
        PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
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
        wprintf_s(L"Cannot determine if the process is running under WoW64: %X\r\n", status);
        goto CLEANUP;
    }

    /* Locate native PEB */

    PROCESS_BASIC_INFORMATION basicInfo;

    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot query PEB location: %X\r\n", status);
        goto CLEANUP;
    }

    if (basicInfo.PebBaseAddress)
    {
        // Read modules from the native PEB
        status = H2EnumerateModulesProcessNative(hProcess, basicInfo.PebBaseAddress);
    }

#ifdef _WIN64
    if (wow64Peb)
    {
        // Read modules from the WoW64 PEB
        status = H2EnumerateModulesProcessWoW64(hProcess, wow64Peb);
    }
#else
    if (!wow64Peb)
    {
        wprintf_s(L"Unable to query 64-bit modules; please use the 64-bit version of the tool.\r\n");
    }
#endif

CLEANUP:
    if (hProcess)
        NtClose(hProcess);

    return status;
}