/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t* argv[])
{
    DWORD error;
    HANDLE hProcess = NULL;
    PVOID remoteFilename = NULL;
    HANDLE hThread = NULL;

    wprintf_s(L"Simplest DLL injection demo by Hunt & Hackett.\r\n\r\n");

    if (argc < 2)
    {
        error = ERROR_INVALID_PARAMETER;
        wprintf_s(L"Usage: SimplestDllInjection.exe [PID] [filename]\r\n");
        goto CLEANUP;
    }

    // Make the filename absolute
    WCHAR filenameBuffer[MAX_PATH];
    SIZE_T filenameSize;
    memset(filenameBuffer, 0, sizeof(filenameBuffer));

    filenameSize = GetFullPathNameW(argv[2], sizeof(filenameBuffer) / sizeof(WCHAR), filenameBuffer, NULL);

    if (!filenameSize)
    {
        error = GetLastError();
        wprintf_s(L"GetFullPathNameW: %d\r\n", error);
        goto CLEANUP;
    }

    filenameSize = filenameSize * sizeof(WCHAR);
    wprintf_s(L"Injecting file: %s\r\n\r\n", (PWSTR)filenameBuffer);

    // Open the target process
    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE,
        wcstoul(argv[1], NULL, 0)
    );
    
    if (!hProcess)
    {
        error = GetLastError();
        wprintf_s(L"OpenProcess: %d\r\n", error);
        goto CLEANUP;
    }

    // Allocate memory for the filename in the target
    remoteFilename = VirtualAllocEx(
        hProcess,
        &remoteFilename,
        filenameSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remoteFilename)
    {
        error = GetLastError();
        wprintf_s(L"VirtualAllocEx: %d\r\n", error);
        goto CLEANUP;
    }

    // Write the filename into the target
    if (!WriteProcessMemory(
        hProcess,
        remoteFilename,
        filenameBuffer,
        filenameSize,
        NULL
    ))
    {
        error = GetLastError();
        wprintf_s(L"WriteProcessMemory: %d\r\n", error);
        goto CLEANUP;
    }

    // Find (shared) address of kernel32.dll
    HMODULE hKernel32;
    hKernel32 = GetModuleHandleW(L"kernel32.dll");

    if (!hKernel32)
    {
        error = GetLastError();
        wprintf_s(L"GetModuleHandleW: %d\r\n", error);
        goto CLEANUP;
    }

    // Find LoadLibrary in it
    PVOID pLoadLibrary;
    pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");

    if (!pLoadLibrary)
    {
        error = GetLastError();
        wprintf_s(L"GetProcAddress: %d\r\n", error);
        goto CLEANUP;
    }

    // Create a remote thread on LoadLibrary
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        pLoadLibrary,
        remoteFilename,
        0,
        NULL
    );

    if (!hThread)
    {
        error = GetLastError();
        wprintf_s(L"CreateRemoteThread: %d\r\n", error);
        goto CLEANUP;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    hProcess = NULL;

    wprintf_s(L"Successfully created remote thread.\r\n");
    error = ERROR_SUCCESS;

CLEANUP:

    if (remoteFilename && hProcess)
        VirtualFreeEx(hProcess, &remoteFilename, filenameSize, MEM_FREE);

    if (hProcess)
        CloseHandle(hProcess);

    return error;
}
