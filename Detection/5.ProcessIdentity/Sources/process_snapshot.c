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

// Enumerate processes on the system
NTSTATUS H2SnapshotProcesses(
    _Out_ PSYSTEM_PROCESS_INFORMATION *Snapshot
)
{
    NTSTATUS status;    
    PSYSTEM_PROCESS_INFORMATION buffer;
    ULONG bufferSize = 0x40;

    do
    {
        status = H2Allocate(bufferSize, &buffer, 0);

        if (!NT_SUCCESS(status))
            break;

        // Snapshot all processes on the system
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (NT_SUCCESS(status))
        {
            *Snapshot = buffer;
            break;
        }
        else
        {
            H2Free(buffer);
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    return status;
}

// Print short process name from the process snapshot
VOID H2PrintProcessName(
    _In_ HANDLE ProcessId
)
{
    NTSTATUS status;
    PSYSTEM_PROCESS_INFORMATION buffer;

    status = H2SnapshotProcesses(&buffer);

    wprintf_s(L"Short name:\r\n  ");

    if (!NT_SUCCESS(status))
    {
        H2PrintStatus(status);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION process = buffer;
    BOOLEAN found = FALSE;

    do
    {
        // Retrieve the first thread ID from a matching process
        if (process->UniqueProcessId == ProcessId)
        {
            if (!process->ImageName.Length)
                wprintf_s(L"(empty)\r\n\r\n");
            else
                wprintf_s(L"%wZ\r\n\r\n", &process->ImageName);

            found = TRUE;
            break;
        }

        // Go to the next one
        if (process->NextEntryOffset)
        {
            (PBYTE)process += process->NextEntryOffset;
            continue;
        }

        break;
    } while (TRUE);

    if (!found)
        wprintf_s(L"(not found)\r\n\r\n");

    H2Free(buffer);
}
