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
#include <wchar.h>

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

FORCEINLINE
VOID H2PrintStatus(
    _In_ NTSTATUS Status
)
{
    switch (Status)
    {
        case STATUS_FILE_DELETED:
            wprintf_s(L"Error: STATUS_FILE_DELETED\r\n\r\n");
            break;

        case STATUS_INVALID_ADDRESS:
            wprintf_s(L"Error: STATUS_INVALID_ADDRESS\r\n\r\n");
            break;

        case STATUS_FILE_INVALID:
            wprintf_s(L"Error: STATUS_FILE_INVALID\r\n\r\n");
            break;

        case STATUS_TRANSACTION_NOT_ACTIVE:
            wprintf_s(L"Error: STATUS_TRANSACTION_NOT_ACTIVE\r\n\r\n");
            break;

        case STATUS_VOLUME_DISMOUNTED:
            wprintf_s(L"Error: STATUS_VOLUME_DISMOUNTED\r\n\r\n");
            break;

        case STATUS_ACCESS_DENIED:
            wprintf_s(L"Error: STATUS_ACCESS_DENIED\r\n\r\n");
            break;

        case STATUS_INVALID_PARAMETER:
            wprintf_s(L"Error: STATUS_INVALID_PARAMETER\r\n\r\n");
            break;

        default:
            wprintf_s(L"Error: 0x%X\r\n\r\n", Status);
    }
}

/* process_info.c */

// Print a process information string
VOID H2PrintStringInfoProcess(
    _In_ HANDLE Process,
    _In_ PROCESSINFOCLASS InfoClass,
    _In_opt_ PCWSTR Comment
);

/* peb_strings.c */

// Print strings from remote PEB
NTSTATUS H2PrintPebStringsProcess(
    _In_ HANDLE Process
);

/* base_module.c */

// Print the file used as the image base of a process
NTSTATUS H2PrintImageBaseFile(
    _In_ HANDLE Process
);

/* process_snapshot.c */

VOID H2PrintProcessName(
    _In_ HANDLE ProcessId
);
