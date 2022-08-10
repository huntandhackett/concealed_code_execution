/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#define PHNT_VERSION PHNT_WIN11
#include <phnt_windows.h>
#include <phnt.h>
#include <minidumpapiset.h>

FORCEINLINE
_Must_inspect_result_
NTSTATUS
H2Allocate(
    _In_ SIZE_T Size,
    _Outptr_ PVOID *Buffer
)
{
    PVOID buffer = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, 0, Size);

    if (buffer)
    {
        *Buffer = buffer;
        return STATUS_SUCCESS;
    }

    return STATUS_NO_MEMORY;
}

FORCEINLINE
VOID
H2Free(
    _In_ _Post_ptr_invalid_ PVOID Buffer
)
{
    RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, Buffer);
}

// Print a textual representation of a timestamp
VOID H2PrintTimestamp(
    _In_ time_t TimeStamp
);

/* live_unloaded_modules.c */

// Retrieve the list of unloaded modules for a specific process
NTSTATUS H2EnumerateUnloadedModulesProcess(
    _In_ ULONG_PTR PID
);

/* minidump_unloaded_modules.c */

// Retrieve the list of unloaded modules from a minidump
NTSTATUS H2EnumerateUnloadedModulesMiniDump(
    _In_ PCWSTR FileName
);

/* make_minidump.c */

// Save a minidump of a process
NTSTATUS H2MakeMiniDump(
    _In_ ULONG_PTR PID,
    _In_ PCWSTR FileName,
    _In_opt_ MINIDUMP_TYPE DumpType
);
