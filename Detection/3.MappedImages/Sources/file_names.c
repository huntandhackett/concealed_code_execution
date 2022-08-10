/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "mapped_images.h"

// Query a name of a memory mapped file at a specific address
NTSTATUS H2QueryFileAtAddress(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING *NativeFileName
)
{
    NTSTATUS status;
    PUNICODE_STRING buffer;
    SIZE_T bufferSize = RtlGetLongestNtPathLength() * sizeof(WCHAR);

    do
    {
        status = H2Allocate(bufferSize, &buffer, 0);

        if (!NT_SUCCESS(status))
            break;

        status = NtQueryVirtualMemory(
            Process,
            Address,
            MemoryMappedFilenameInformation,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (NT_SUCCESS(status))
        {
            *NativeFileName = buffer;
            break;
        }
        else
        {
            H2Free(buffer);
        }

    } while (status == STATUS_BUFFER_OVERFLOW);

    return status;
}

// Convert a native filename to a normalized DOS form
NTSTATUS H2NativeNameToDosName(
    _In_ PUNICODE_STRING NativeFileName,
    _Out_ PUNICODE_STRING *DosFileName
)
{
    NTSTATUS status;
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK isb;

    // Open the file for retrieving its name back
    InitializeObjectAttributes(&objAttr, NativeFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(
        &hFile,
        SYNCHRONIZE,
        &objAttr,
        &isb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        return status;

    PWCHAR buffer;
    ULONG bufferLength = RtlGetLongestNtPathLength();
    ULONG required;

    do
    {
        status = H2Allocate(bufferLength * sizeof(WCHAR), &buffer, 0);

        if (!NT_SUCCESS(status))
            break;

        // Retrieve a normalized DOS name for the file
        required = GetFinalPathNameByHandleW(
            hFile,
            buffer,
            bufferLength,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
        );

        if (required >= bufferLength)
            status = STATUS_BUFFER_TOO_SMALL;
        else if (required == 0)
            status = NTSTATUS_FROM_WIN32(GetLastError());
        else
            status = STATUS_SUCCESS;

        if (!NT_SUCCESS(status))
        {
            H2Free(buffer);
        }
    }
    while (status == STATUS_BUFFER_TOO_SMALL);

    NtClose(hFile);

    if (!NT_SUCCESS(status))
        return status;

    UNICODE_STRING dosFileBuffer;
    dosFileBuffer.Buffer = buffer;
    dosFileBuffer.MaximumLength = (USHORT)(bufferLength * sizeof(WCHAR));
    dosFileBuffer.Length = (USHORT)(required * sizeof(WCHAR));

    UNICODE_STRING knownPrefix;
    RtlInitUnicodeString(&knownPrefix, L"\\\\?\\");

    if (RtlPrefixUnicodeString(&knownPrefix, &dosFileBuffer, FALSE))
    {
        // Remove the \\?\ prefix
        dosFileBuffer.Buffer += knownPrefix.Length / sizeof(WCHAR);
        dosFileBuffer.MaximumLength -= knownPrefix.Length;
        dosFileBuffer.Length -= knownPrefix.Length;
    }

    PUNICODE_STRING dosFileName;
    status = H2Allocate(sizeof(UNICODE_STRING) + dosFileBuffer.MaximumLength, &dosFileName, 0);

    if (NT_SUCCESS(status))
    {
        // Copy the DOS filename
        dosFileName->Buffer = (PWCHAR)RtlOffsetToPointer(dosFileName, sizeof(UNICODE_STRING));
        dosFileName->Length = dosFileBuffer.Length;
        dosFileName->MaximumLength = dosFileBuffer.MaximumLength;
        memcpy_s(dosFileName->Buffer, dosFileName->Length, dosFileBuffer.Buffer, dosFileBuffer.Length);
        *DosFileName = dosFileName;
    }
    
    H2Free(buffer);
    return status;
}