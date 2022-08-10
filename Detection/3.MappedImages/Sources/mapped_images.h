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

FORCEINLINE
_Must_inspect_result_
NTSTATUS
H2Allocate(
    _In_ SIZE_T Size,
    _Outptr_ PVOID* Buffer,
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

/* file_names.c */

NTSTATUS H2QueryFileAtAddress(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING *NativeFileName
);

NTSTATUS H2NativeNameToDosName(
    _In_ PUNICODE_STRING NativeFileName,
    _Out_ PUNICODE_STRING *DosFileName
);

/* live_mapped_images.c */

NTSTATUS H2PrintMappedImagesProcessID(
    _In_ HANDLE ProcessID
);
