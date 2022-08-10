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

#ifdef AUTO_UNLOAD
#define LOAD_RESULT FALSE
#else
#define LOAD_RESULT TRUE
#endif

BOOL
WINAPI
DllMain(
    HMODULE hModule,
    DWORD dwReason,
    LPVOID lpReserved
)
{
    if (dwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    STARTUPINFOW startupInfo = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION processInfo;
    WCHAR fileNameBuffer[MAX_PATH];

    if (!ExpandEnvironmentStringsW(
        L"%SystemRoot%\\system32\\cmd.exe",
        fileNameBuffer,
        sizeof(fileNameBuffer) / sizeof(WCHAR)
    ))
        return FALSE;

    if (!CreateProcessW(
        fileNameBuffer,
        NULL,
        NULL,
        NULL,
        TRUE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &startupInfo,
        &processInfo
    ))
        return FALSE;

    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    return LOAD_RESULT;
}

