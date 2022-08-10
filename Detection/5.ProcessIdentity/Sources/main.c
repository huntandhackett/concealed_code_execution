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
#include <stdio.h>
#include <wchar.h>

int wmain(int argc, wchar_t* argv[])
{
    wprintf_s(L"A tool for inspecting identity of a process by Hunt & Hackett.\r\n\r\n");

    if (argc <= 1)
    {
        wprintf_s(L"Usage:\r\n\r\n");
        wprintf_s(L"  ProcessIdentity.exe [PID] - show image and command line information.\r\n");

        return STATUS_INVALID_PARAMETER;
    }

#ifndef _WIN64
    if (NtCurrentTeb()->WowTebOffset)
    {
        wprintf_s(L"Please use the 64-bit version of the tool.\r\n");
        return STATUS_WOW_ASSERTION;
    }
#endif

    NTSTATUS status;
    HANDLE hProcess;
    CLIENT_ID clientId = {0};
    OBJECT_ATTRIBUTES objAttr;

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)wcstoul(argv[1], NULL, 0);
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    
    status = NtOpenProcess(
        &hProcess,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        &objAttr,
        &clientId
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot open the target process: 0x%X\r\n", status);
        return status;
    }

    H2PrintProcessName(clientId.UniqueProcess);
    H2PrintStringInfoProcess(hProcess, ProcessImageFileName, L"Image name (Native)");
    H2PrintImageBaseFile(hProcess);

    H2PrintStringInfoProcess(hProcess, ProcessImageFileNameWin32, L"Image name (Win32)");
    H2PrintPebStringsProcess(hProcess);

    return status;
}
