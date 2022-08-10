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

// Save a minidump of a process
NTSTATUS H2MakeMiniDump(
	_In_ ULONG_PTR PID,
	_In_ PCWSTR FileName,
	_In_opt_ MINIDUMP_TYPE DumpType
)
{
	NTSTATUS status;
    UNICODE_STRING ntFileName;
    HANDLE hFile = NULL;
	HANDLE hProcess = NULL;

    /* Convert the filename to NT format */

    status = RtlDosLongPathNameToNtPathName_U_WithStatus(
        FileName,
        &ntFileName,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot convert the filename to NT format: %X\r\n", status);
        goto CLEANUP;
    }

	/* Open the target process */

	CLIENT_ID clientId;
	clientId.UniqueProcess = (HANDLE)PID;
	clientId.UniqueThread = NULL;

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = NtOpenProcess(
        &hProcess,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &objAttr,
        &clientId
    );

    /* Create a file for the minidump */

    IO_STATUS_BLOCK isb;
    InitializeObjectAttributes(&objAttr, &ntFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(
        &hFile,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &isb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        if (status == STATUS_OBJECT_NAME_COLLISION)
            wprintf_s(L"Cannot create a file for the minidump: file already exists.\r\n");
        else
            wprintf_s(L"Cannot create a file for the minidump: %X\r\n", status);
        goto CLEANUP;
    }

    /* Save the minidump */

    if (!MiniDumpWriteDump(
        hProcess,
        0,
        hFile,
        DumpType,
        NULL,
        NULL,
        NULL
    ))
    {
        // Use the last status when available, otherwise use the last error
        if (RtlNtStatusToDosErrorNoTeb(RtlGetLastNtStatus()) == RtlGetLastWin32Error())
            status = RtlGetLastNtStatus();
        else
            status = NTSTATUS_FROM_WIN32(RtlGetLastWin32Error());

        wprintf_s(L"Cannot create a minidump: %X\r\n", status);
        goto CLEANUP;
    }

    wprintf_s(L"Success.\r\n");
    status = STATUS_SUCCESS;

CLEANUP:
    if (ntFileName.Buffer)
        RtlFreeUnicodeString(&ntFileName);

    if (hProcess)
        NtClose(hProcess);

    if (hFile)
        NtClose(hFile);

    return status;
}
