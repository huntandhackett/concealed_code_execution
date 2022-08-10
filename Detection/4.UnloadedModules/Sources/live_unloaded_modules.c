/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "unloaded_modules.h"
#include <wchar.h>
#include <search.h>

int __cdecl SortCallback(void* context, void const* elem1, void const* elem2)
{
    return ((PRTL_UNLOAD_EVENT_TRACE)elem1)->Sequence - ((PRTL_UNLOAD_EVENT_TRACE)elem2)->Sequence;
}

// Retrieve the list of unloaded modules for a specific process
NTSTATUS H2EnumerateUnloadedModulesProcess(
    _In_ ULONG_PTR PID
)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    PRTL_UNLOAD_EVENT_TRACE trace = NULL;

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

    ULONG_PTR wow64Info;

    status = NtQueryInformationProcess(
        hProcess,
        ProcessWow64Information,
        &wow64Info,
        sizeof(wow64Info),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot determine if the process is running under WoW64: %X\r\n", status);
        goto CLEANUP;
    }

    if (!!NtCurrentTeb()->WowTebOffset ^ !!wow64Info)
    {
        status = STATUS_WOW_ASSERTION;
        wprintf_s(L"Unable to query. Please use the %s-bit version of the tool.\r\n", wow64Info ? L"32" : L"64");
        goto CLEANUP;
    }

    /* Retrieve system-wide addresses of the trace information */

    PULONG pRtlpUnloadEventTraceExSize;
    PULONG pRtlpUnloadEventTraceExNumber;
    PVOID pRtlpUnloadEventTraceEx;

    RtlGetUnloadEventTraceEx(
        &pRtlpUnloadEventTraceExSize,
        &pRtlpUnloadEventTraceExNumber,
        &pRtlpUnloadEventTraceEx
    );

    /* Read trace element size */

    ULONG size;

    status = NtReadVirtualMemory(
        hProcess,
        pRtlpUnloadEventTraceExSize,
        &size,
        sizeof(size),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read trace element size: %X\r\n", status);
        goto CLEANUP;
    }

    if (size < sizeof(RTL_UNLOAD_EVENT_TRACE))
    {
        status = STATUS_UNKNOWN_REVISION;
        wprintf_s(L"Trace elements are too small.\r\n");
        goto CLEANUP;
    }

    /* Read trace element count */

    ULONG count;

    status = NtReadVirtualMemory(
        hProcess,
        pRtlpUnloadEventTraceExNumber,
        &count,
        sizeof(count),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read trace element count: %X\r\n", status);
        goto CLEANUP;
    }

    /* Read trace buffer location */

    PVOID tracePtr;

    status = NtReadVirtualMemory(
        hProcess,
        pRtlpUnloadEventTraceEx,
        &tracePtr,
        sizeof(tracePtr),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read trace pointer: %X\r\n", status);
        goto CLEANUP;
    }

    if (!tracePtr)
    {
        wprintf_s(L"No unloaded modules found.\r\n");
        goto CLEANUP;
    }

    /* Allocate memory for copying the trace*/

    SIZE_T traceSize;
    traceSize = (SIZE_T)size * count;

    status = H2Allocate(traceSize, &trace);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot allocate memory for the trace.\r\n");
        goto CLEANUP;
    }

    /* Read the trace buffer */

    status = NtReadVirtualMemory(
        hProcess,
        tracePtr,
        trace,
        traceSize,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read the trace: %X\r\n", status);
        goto CLEANUP;
    }

    /* Sort the items based on the sequence number */

    qsort_s(trace, count, size, SortCallback, NULL);

    /* Count the number of valid entries */

    PRTL_UNLOAD_EVENT_TRACE traceEntry;
    ULONG availableCount;
    
    availableCount = 0;
    traceEntry = trace;

    for (ULONG i = 0; i < count; i++)
    {
        if (traceEntry->BaseAddress)
            availableCount++;

        (ULONG_PTR)traceEntry += size;
    }

    wprintf_s(
        L"The trace includes details for %u out of %u module unload events.\r\n\r\n",
        availableCount,
        availableCount + (count > 0 ? trace[0].Sequence : 0)
    );

    /* Output the trace */

    traceEntry = trace;

    for (ULONG i = 0; i < count; i++)
    {
        if (trace[i].BaseAddress)
        {

            trace[i].ImageName[RTL_NUMBER_OF(trace[i].ImageName) - 1] = '\0';

            wprintf_s(L"[%u] %s (version %u.%u.%u.%u)\r\n",
                trace[i].Sequence,
                trace[i].ImageName,
                trace[i].Version[0] >> 16,
                trace[i].Version[0] & 0xFFFF,
                trace[i].Version[1] >> 16,
                trace[i].Version[1] & 0xFFFF
            );

            wprintf_s(L"  Address range:  0x%p-0x%p (%zu KiB)\r\n",
                trace[i].BaseAddress,
                RtlOffsetToPointer(trace[i].BaseAddress, trace[i].SizeOfImage - 1),
                trace[i].SizeOfImage >> 10
            );

            wprintf_s(L"  File timestamp: ");
            H2PrintTimestamp(trace[i].TimeDateStamp);
            wprintf_s(L"\r\n  File checksum:  0x%0.6X\r\n\r\n", trace[i].CheckSum);
        }

        (ULONG_PTR)traceEntry += size;
    }


CLEANUP:
    if (hProcess)
        NtClose(hProcess);

    if (trace)
        H2Free(trace);

    return status;
}
