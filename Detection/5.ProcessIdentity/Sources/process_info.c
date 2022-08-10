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

// Query a string information about a process
NTSTATUS H2QueryStringProcess(
	_In_ HANDLE Process,
	_In_ PROCESSINFOCLASS InfoClass,
	_Out_ PUNICODE_STRING *String
)
{
    NTSTATUS status;
    ULONG bufferSize = RtlGetLongestNtPathLength() * sizeof(WCHAR);
    PUNICODE_STRING buffer;

    do
    {
        status = H2Allocate(bufferSize, &buffer, 0);

        if (!NT_SUCCESS(status))
            break;

        status = NtQueryInformationProcess(
            Process,
            InfoClass,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (NT_SUCCESS(status))
        {
            *String = buffer;
            break;
        }
        else
        {
            H2Free(buffer);
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    return status;
}

// Print a process information string
VOID H2PrintStringInfoProcess(
    _In_ HANDLE Process,
    _In_ PROCESSINFOCLASS InfoClass,
    _In_opt_ PCWSTR Comment
)
{
    NTSTATUS status;
    PUNICODE_STRING string;

    status = H2QueryStringProcess(Process, InfoClass, &string);

    if (Comment)
        wprintf_s(L"%s:\r\n  ", Comment);

    if (NT_SUCCESS(status))
    {
        wprintf_s(L"%wZ\r\n\r\n", string);
        H2Free(string);
    }
    else
    {
        H2PrintStatus(status);
    }
}
