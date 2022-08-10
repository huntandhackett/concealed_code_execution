/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#define PHNT_VERSION PHNT_21H1
#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>
#include <wchar.h>

int wmain(int argc, wchar_t* argv[])
{
    NTSTATUS status;
    UNICODE_STRING fileName = { 0 };
    HANDLE hFile = NULL;
    HANDLE hFileAlt = NULL;
    PVOID data = NULL;
    ULONG dataSize = 0;

    wprintf_s(L"Unlocking running executable for deletion - demo by Hunt & Hackett.\r\n\r\n");

    if (argc < 2)
    {
        wprintf_s(L"Usage:\r\n\r\n");
        wprintf_s(L"  UnlockExe.exe [Filename] - unlock an executable file for deletion.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Convert the filename to NT format
    status = RtlDosLongPathNameToNtPathName_U_WithStatus(
        argv[1],
        &fileName,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot convert the name to NT format: 0x%X\r\n", status);
        goto CLEANUP;
    }

    // Open the primary stream for making a backup and deleting
    IO_STATUS_BLOCK isb;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(
        &hFile,
        FILE_READ_DATA | DELETE | SYNCHRONIZE,
        &objAttr,
        &isb,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot open the file: 0x%X", status);
        goto CLEANUP;
    }

    // Determine content size
    FILE_STANDARD_INFORMATION fileInfo;

    status = NtQueryInformationFile(
        hFile,
        &isb,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot determine file size: 0x%X", status);
        goto CLEANUP;
    }

    // Allocate a buffer for storing the data
    dataSize = fileInfo.EndOfFile.LowPart;

    data = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, 0, dataSize);

    if (!data)
    {
        status = STATUS_NO_MEMORY;
        wprintf_s(L"Cannot allocate a buffer for a backup");
        goto CLEANUP;
    }

    // Read the data
    status = NtReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &isb,
        data,
        dataSize,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot read file data: 0x%X", status);
        goto CLEANUP;
    }

    // Create an alternative stream for backing up the content
    UNICODE_STRING backupStream;

    RtlInitUnicodeString(&backupStream, L":backup");
    InitializeObjectAttributes(&objAttr, &backupStream, OBJ_CASE_INSENSITIVE, hFile, NULL);

    status = NtCreateFile(
        &hFileAlt,
        FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
        &objAttr,
        &isb,
        &fileInfo.EndOfFile,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot create a backup stream: 0x%X", status);
        goto CLEANUP;
    }

    // Write the data to the backup stream
    status = NtWriteFile(
        hFileAlt,
        NULL,
        NULL,
        NULL,
        &isb,
        data,
        dataSize,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot wirte the backup stream: 0x%X", status);
        goto CLEANUP;
    }

    // Move the locked main stream to an alternative stream
    #define NEW_NAME_LENGTH 7
    BYTE renameBuffer[sizeof(FILE_RENAME_INFORMATION) + NEW_NAME_LENGTH * sizeof(WCHAR) + sizeof(UNICODE_NULL)];
    PFILE_RENAME_INFORMATION renameInfo;

    renameInfo = (PVOID)&renameBuffer;
    wcscpy_s(renameInfo->FileName, NEW_NAME_LENGTH + sizeof(UNICODE_NULL), L":unlock");
    renameInfo->FileNameLength = NEW_NAME_LENGTH * sizeof(WCHAR);
    renameInfo->ReplaceIfExists = FALSE;
    renameInfo->RootDirectory = NULL;

    status = NtSetInformationFile(
        hFile,
        &isb,
        renameBuffer,
        sizeof(renameBuffer),
        FileRenameInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot move the main stream: 0x%X", status);
        goto CLEANUP;
    }

    // Move the backup stream to the main stream
    wcscpy_s(renameInfo->FileName, NEW_NAME_LENGTH + sizeof(UNICODE_NULL), L"::$DATA");
    renameInfo->ReplaceIfExists = TRUE;

    status = NtSetInformationFile(
        hFileAlt,
        &isb,
        renameBuffer,
        sizeof(renameBuffer),
        FileRenameInformation
    );

    if (!NT_SUCCESS(status))
    {
        // Failed, undo the changes...

        // Move the original steam back
        NtSetInformationFile(
            hFile,
            &isb,
            renameBuffer,
            sizeof(renameBuffer),
            FileRenameInformation
        );

        // Delete the supplimentary backup stream
        FILE_DISPOSITION_INFORMATION disposition;
        disposition.DeleteFile = TRUE;

        NtSetInformationFile(
            hFileAlt,
            &isb,
            &disposition,
            sizeof(disposition),
            FileDispositionInformation
        );

        wprintf_s(L"Cannot restore the backup stream: 0x%X", status);
        goto CLEANUP;
    }

    // Delete the original (currently renamed) stream
    FILE_DISPOSITION_INFORMATION disposition;
    disposition.DeleteFile = TRUE;

    status = NtSetInformationFile(
        hFile,
        &isb,
        &disposition,
        sizeof(disposition),
        FileDispositionInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot delete the original stream: 0x%X", status);
        goto CLEANUP;
    }

    status = STATUS_SUCCESS;
    wprintf_s(L"File unlocked successfully!");

CLEANUP:

    if (fileName.Buffer)
        RtlFreeUnicodeString(&fileName);

    if (hFile)
        NtClose(hFile);

    if (data)
        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, data);

    if (hFileAlt)
        NtClose(hFileAlt);

    return status;
}
