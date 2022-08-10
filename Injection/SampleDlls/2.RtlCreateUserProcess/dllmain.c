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
#define PHNT_NO_INLINE_INIT_STRING
#include <phnt_windows.h>
#include <phnt.h>

#ifdef AUTO_UNLOAD
#define LOAD_RESULT FALSE
#else
#define LOAD_RESULT TRUE
#endif

ULONG
WINAPI
NtDllMain(
    PVOID hModule,
    ULONG ulReason,
    LPVOID lpReserved
)
{
    if (ulReason != DLL_PROCESS_ATTACH)
        return TRUE;
 
    NTSTATUS status;
    UNICODE_STRING imageName;
    PRTL_USER_PROCESS_PARAMETERS processParams;
    RTL_USER_PROCESS_INFORMATION processInfo;

    RtlInitUnicodeString(&imageName, L"\\SystemRoot\\system32\\cmd.exe");

    status = RtlCreateProcessParametersEx(
        &processParams,
        &imageName,
        NULL,
        NULL,
        NULL,
        NULL,
        &imageName,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );

    if (!NT_SUCCESS(status))
        return FALSE;

    status = RtlCreateUserProcess(
        &imageName,
        0,
        processParams,
        NULL,
        NULL,
        NtCurrentProcess(),
        TRUE,
        NULL,
        NULL,
        &processInfo
    );

    RtlDestroyProcessParameters(processParams);

    if (!NT_SUCCESS(status))
        return FALSE;

    NtResumeThread(processInfo.ThreadHandle, NULL);
    NtClose(processInfo.ProcessHandle);
    NtClose(processInfo.ThreadHandle);

    return LOAD_RESULT;
}

