/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "manual_mapping.h"
#include <stdio.h>
#include <wchar.h>

int wmain(int argc, wchar_t* argv[])
{
    NTSTATUS status;
    PCWSTR lastCall;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID data = NULL;
    PVOID localImage = NULL;
    PVOID remoteImage = NULL;

    wprintf_s(L"DLL injection via manual mapping - demo by Hunt & Hackett.\r\n\r\n");

    if (argc < 2)
    {
        wprintf_s(L"Usage: ManualDllMapping.exe [PID] [filename]\r\n");
        status = STATUS_INVALID_PARAMETER;
        goto CLEANUP;
    }

    // Open the target process
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttr;

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)wcstoul(argv[1], NULL, 0);
    clientId.UniqueThread = 0;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = NtOpenProcess(
        &hProcess,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        &objAttr,
        &clientId
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtOpenProcess: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine target's bitness
    ULONG_PTR wow64Peb;

    status = NtQueryInformationProcess(
        hProcess,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        NULL
    );


    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationProcess [ProcessWow64Information]: %x\r\n", status);
        goto CLEANUP;
    }

#ifndef _WIN64
    if (!wow64Peb)
    {
        wprintf_s(L"Cannot inject from a 32-bit to a 64-bit process. \
            Please use a 64-bit version of the tool instead.");
        status = STATUS_WOW_ASSERTION;
        goto CLEANUP;
    }
#endif

    // Convert the filename to NT format
    UNICODE_STRING fileName;

    status = RtlDosPathNameToNtPathName_U_WithStatus(
        argv[2],
        &fileName,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"RtlDosPathNameToNtPathName_U_WithStatus: %x\r\n", status);
        goto CLEANUP;
    }

    wprintf_s(L"Injecting file: %s\r\n\r\n", fileName.Buffer);
    
    // Map the DLL as a data stream
    SIZE_T dataSize;

    status = H2MapReadOnlyFile(
        &fileName,
        SEC_COMMIT,
        &data,
        &dataSize,
        &lastCall
    );

    RtlFreeUnicodeString(&fileName);
    memset(&fileName, 0, sizeof(fileName));

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"%s failed while reading the source DLL: %x\r\n", lastCall, status);
        goto CLEANUP;
    }

    // Start parsing the DLL
    PIMAGE_NT_HEADERS imageNtHeader;
    status = RtlImageNtHeaderEx(
        0,
        data,
        dataSize,
        &imageNtHeader
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"RtlImageNtHeaderEx on the source DLL: %x\r\n", status);
        goto CLEANUP;
    }

    // Check bitness compatibility
    status = H2IsImageCompatible(imageNtHeader, !!wow64Peb);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"The DLL is incompatible with the process: %x\r\n", status);
        goto CLEANUP;
    }

    // Create a shared memory region with the target and deploy the image there.
    // This operation will parse the PE structures and change the layout and remote
    // memory protection accordingly.

    SIZE_T imageSize;

    status = H2MapImagesFromData(
        data,
        dataSize,
        hProcess,
        &localImage,
        &remoteImage,
        &imageSize,
        &lastCall
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"%s failed while deploying the image: %x\r\n", lastCall, status);
        goto CLEANUP;
    }

    // Perform image relocation if necessary
    status = H2ApplyRelocations(localImage, imageSize, (ULONG64)remoteImage);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Error while appliying relocations: %x\r\n", status);
        goto CLEANUP;
    }

    // TODO: resolve imports
    status = H2ResoleImports(hProcess, localImage, imageSize);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Error while resolving imports: %x\r\n", status);
        goto CLEANUP;
    }

    // Find RtlExitUserThread
    PVOID rtlExitUserThread;

    status = H2FindKnownDllExport(
        wow64Peb ? L"\\KnownDlls32\\ntdll.dll" : L"\\KnownDlls\\ntdll.dll",
        "RtlExitUserThread",
        &rtlExitUserThread,
        &lastCall
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"%s failed while locating RtlExitUserThread: %x\r\n", lastCall, status);
        goto CLEANUP;
    }

    // Create a thread on RtlExitUserThread
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        rtlExitUserThread,
        (PVOID)(ULONG_PTR)STATUS_SUCCESS,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        0,
        0,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateThreadEx: %x\r\n", status);
        goto CLEANUP;
    }

    // Queue an APC for executing DllMain of the library
    status = NtQueueApcThread(
        hThread,
        RtlOffsetToPointer(remoteImage, imageNtHeader->OptionalHeader.AddressOfEntryPoint),
        remoteImage,                           // hinstDLL
        (PVOID)(ULONG_PTR)DLL_PROCESS_ATTACH,  // fdwReason
        NULL                                   // lpvReserved
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueueApcThread for DllMain: %x\r\n", status);
        goto CLEANUP;
    }

    // Execute pending APCs
    status = NtResumeThread(hThread, NULL);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtResumeThread: %x\r\n", status);
        goto CLEANUP;
    }

    // Wait for completion
    wprintf_s(L"Created a remote thread, waiting for it...\r\n");
    status = NtWaitForSingleObject(hThread, FALSE, NULL);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtWaitForSingleObject: %x\r\n", status);
        goto CLEANUP;
    }

    wprintf_s(L"Successfully injected the DLL.\r\n");
    status = STATUS_SUCCESS;

    // Prevent unmapping
    remoteImage = NULL;

CLEANUP:
    if (data)
        NtUnmapViewOfSection(NtCurrentProcess(), data);

    if (localImage)
        NtUnmapViewOfSection(NtCurrentProcess(), localImage);

    if (hProcess && remoteImage)
        NtUnmapViewOfSection(hProcess, remoteImage);

    if (hProcess)
        NtClose(hProcess);

    return status;
}

