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

#ifdef _WIN64
#define BITNESS L"64"
#else
#define BITNESS L"32"
#endif

FORCEINLINE
_Must_inspect_result_
NTSTATUS
H2Allocate(
    _In_ SIZE_T Size,
    _Outptr_ PVOID *Buffer,
    _In_ ULONG Flags
)
{
    PVOID buffer = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, Flags, Size);

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

/* print_helper.c */

VOID H2PrintTimestamp(
    _In_ time_t TimeStamp
);

// Print details about a loaded module
VOID H2PrintProcessModule(
    _In_ HANDLE Process,
    _In_ ULONG Index,
    _In_ PCWSTR BaseDllName,
    _In_ WORD BaseDllNameLength,
    _In_ PCWSTR FullDllName,
    _In_ WORD FullDllNameLength,
    _In_ ULONG_PTR BaseAddress,
    _In_ SIZE_T ImageSize,
    _In_ ULONG TimeDateStamp,
    _In_ LONGLONG LoadTime,
    _In_ LDR_DLL_LOAD_REASON LoadReason
);

/* live_loaded_modules.c */

// Print the list of modules from a live process
NTSTATUS H2EnumerateModulesProcess(
    _In_ ULONG_PTR PID
);

/* minidump_loaded_modules.c */

// Retrieve the list of modules from a minidump
NTSTATUS H2EnumerateModulesMiniDump(
    _In_ PCWSTR FileName
);

/* make_minidump.c */

// Save a minidump of a process
NTSTATUS H2MakeMiniDump(
    _In_ ULONG_PTR PID,
    _In_ PCWSTR FileName,
    _In_opt_ MINIDUMP_TYPE DumpType
);
