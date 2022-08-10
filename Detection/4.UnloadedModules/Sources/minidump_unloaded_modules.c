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

// Retrieve the list of unloaded modules from a minidump
NTSTATUS H2EnumerateUnloadedModulesMiniDump(
    _In_ PCWSTR FileName
)
{
    NTSTATUS status;
    UNICODE_STRING ntFileName = { 0 };
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    PMINIDUMP_HEADER minidumpBase = NULL;
    SIZE_T minidumpSize = 0;

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

    /* Open the minidump file */

    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK isb;
    InitializeObjectAttributes(&objAttr, &ntFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(
        &hFile,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &isb,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot open the file: %X\r\n", status);
        goto CLEANUP;
    }

    /* Create a memory projection from the file */

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        &objAttr,
        NULL,
        PAGE_READONLY,
        SEC_COMMIT,
        hFile
    );

    NtClose(hFile);
    hFile = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot create a section from the file: %X\r\n", status);
        goto CLEANUP;
    }

    /* Map the minidump */

    status = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &minidumpBase,
        0,
        0,
        NULL,
        &minidumpSize,
        ViewShare,
        0,
        PAGE_READONLY
    );

    NtClose(hSection);
    hSection = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Cannot map the file: %X\r\n", status);
        goto CLEANUP;
    }

    /* Validate the headers and the stream directory */

    if (minidumpSize < sizeof(MINIDUMP_HEADER) ||
        minidumpBase->Signature != MINIDUMP_SIGNATURE ||
        (minidumpBase->Version & 0xFFFF) != MINIDUMP_VERSION ||
        (ULONG64)minidumpBase->StreamDirectoryRva + 
            minidumpBase->NumberOfStreams * sizeof(MINIDUMP_DIRECTORY) >= minidumpSize)
    {
        status = STATUS_BAD_DATA;
        wprintf_s(L"The file doesn't appear to be a valid minidump file.\r\n");
        goto CLEANUP;
    }

    /* Find the stream with the list of unloaded modules */

    PMINIDUMP_DIRECTORY directories;
    directories = RVA_TO_ADDR(minidumpBase, minidumpBase->StreamDirectoryRva);

    MINIDUMP_LOCATION_DESCRIPTOR *streamLocation;
    streamLocation = NULL;

    for (ULONG i = 0; i < minidumpBase->NumberOfStreams; i++)
        if (directories[i].StreamType == UnloadedModuleListStream)
        {
            streamLocation = &directories[i].Location;
            break;
        }

    if (!streamLocation)
    {
        status = STATUS_NOT_FOUND;
        wprintf_s(L"The minidump does not include the list of unloded modules.\r\n");
        goto CLEANUP;
    }

    if ((ULONG64)streamLocation->Rva + streamLocation->DataSize >= minidumpSize)
    {
        status = STATUS_BAD_DATA;
        wprintf_s(L"The minidump stream is out of bound.\r\n");
        goto CLEANUP;
    }

    /* Validate the list of modules */

    PMINIDUMP_UNLOADED_MODULE_LIST modules;
    modules = RVA_TO_ADDR(minidumpBase, streamLocation->Rva);

    if ((ULONG64)modules->SizeOfEntry * modules->SizeOfEntry +
        modules->SizeOfHeader >= streamLocation->DataSize)
    {
        status = STATUS_BAD_DATA;
        wprintf_s(L"The the list of modules is out of bound.\r\n");
        goto CLEANUP;
    }

    PMINIDUMP_UNLOADED_MODULE moduleEntry;
    moduleEntry = RVA_TO_ADDR(modules, modules->SizeOfHeader);

    for (ULONG i = 0; i < modules->NumberOfEntries; i++)
    {
        PMINIDUMP_STRING moduleName;
        moduleName = RVA_TO_ADDR(minidumpBase, moduleEntry->ModuleNameRva);
        
        if (moduleEntry->ModuleNameRva >= minidumpSize ||
            moduleEntry->ModuleNameRva + sizeof(ULONG) + moduleName->Length >= minidumpSize)
        {
            status = STATUS_BAD_DATA;
            wprintf_s(L"Module name is out of bound.\r\n");
            goto CLEANUP;
        }

        moduleEntry = RVA_TO_ADDR(moduleEntry, modules->SizeOfEntry);
    }

    /* Output modules */

    wprintf_s(L"The dump includes details for %u unload events.\r\n\r\n", modules->NumberOfEntries);

    for (ULONG i = 0; i < modules->NumberOfEntries; i++)
    {
        PMINIDUMP_STRING pModuleName;
        WCHAR moduleName[33];

        pModuleName = RVA_TO_ADDR(minidumpBase, moduleEntry->ModuleNameRva); 
        memset(moduleName, 0, sizeof(moduleName));
        memcpy_s(moduleName, sizeof(moduleName), pModuleName->Buffer, pModuleName->Length);

        wprintf_s(L"%s\r\n", moduleName);

        wprintf_s(L"  Address range:  0x%I64X-0x%I64X (%u KiB)\r\n",
            moduleEntry->BaseOfImage,
            moduleEntry->BaseOfImage + moduleEntry->SizeOfImage - 1,
            moduleEntry->SizeOfImage >> 10
        );

        wprintf_s(L"  File timestamp: ");
        H2PrintTimestamp(moduleEntry->TimeDateStamp);
        wprintf_s(L"\r\n  File checksum:  0x%X\r\n\r\n", moduleEntry->CheckSum);

        moduleEntry = RVA_TO_ADDR(moduleEntry, modules->SizeOfEntry);
    }
    
CLEANUP:
    if (ntFileName.Buffer)
        RtlFreeUnicodeString(&ntFileName);

    if (hFile)
        NtClose(hFile);

    if (hSection)
        NtClose(hSection);

    if (minidumpBase)
        NtUnmapViewOfSection(NtCurrentProcess(), minidumpBase);

    return status;
}
