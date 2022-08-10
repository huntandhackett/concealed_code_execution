/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "loaded_modules.h"
#include <time.h>
#include <wchar.h>

#define TIMESTAMP_STRING_LENGTH 20
#define NATIVE_SECOND 10000000
#define SECONDS_IN_DAY 86400
#define DAYS_BETWEEN_1601_AND_1970 134774
#define NATIVE_TO_UNIX_SHIFT ((ULONGLONG)DAYS_BETWEEN_1601_AND_1970 * SECONDS_IN_DAY)

time_t H2NativeTimeToUnixTime(
    _In_ LONGLONG NativeTime
)
{
    return NativeTime / NATIVE_SECOND - NATIVE_TO_UNIX_SHIFT;
}

// Print a textual representation of a timestamp
VOID H2PrintTimestamp(
    _In_ time_t TimeStamp
)
{
    // Adjust for the current timezone
    PLARGE_INTEGER timeZoneBias = (PLARGE_INTEGER)(&USER_SHARED_DATA->TimeZoneBias); 
    TimeStamp -= timeZoneBias->QuadPart / NATIVE_SECOND;

    // Convert to calendar tim
    struct tm calendarTime;
    gmtime_s(&calendarTime, &TimeStamp);

    // Construct the string
    WCHAR buffer[TIMESTAMP_STRING_LENGTH];
    memset(buffer, 0, TIMESTAMP_STRING_LENGTH * sizeof(WCHAR));
    wcsftime(buffer, TIMESTAMP_STRING_LENGTH, L"%F %T", &calendarTime);

    wprintf_s(L"%s", buffer);
}

// Convert a load reason constant to string
PCWSTR H2LoadReasonToString(
    _In_ LDR_DLL_LOAD_REASON LoadReason
)
{
    switch (LoadReason)
    {
        case LoadReasonStaticDependency:
            return L"Static Dependency";

        case LoadReasonStaticForwarderDependency:
            return L"Static Forwarder Dependency";

        case LoadReasonDynamicForwarderDependency:
            return L"Dynamic Forwarder Dependency";

        case LoadReasonDelayloadDependency:
            return L"Delayed Dependency";

        case LoadReasonDynamicLoad:
            return L"Dynamic";

        case LoadReasonAsImageLoad:
            return L"As Image";

        case LoadReasonAsDataLoad:
            return L"As Data";

        case LoadReasonEnclavePrimary:
            return L"Enclave Primary";

        case LoadReasonEnclaveDependency:
            return L"Enclave Dependency";

        case LoadReasonUnknown:
            return L"Unknown";

        default:
            return L"Other";
    }
}

// Read a string from a process and print it
NTSTATUS H2PrintProcessString(
    HANDLE Process,
    PCWSTR String,
    WORD StringLength
)
{
    NTSTATUS status;
    PWSTR buffer;

    status = H2Allocate(
        StringLength + sizeof(UNICODE_NULL),
        &buffer,
        HEAP_ZERO_MEMORY
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"(Failed to allocate)");
        return status;
    }

    status = NtReadVirtualMemory(
        Process,
        (PVOID)String,
        buffer,
        StringLength,
        NULL
    );

    if (NT_SUCCESS(status))
        wprintf_s(L"%s", buffer);
    else
        wprintf_s(L"(Failed to read: %X)", status);

    H2Free(buffer);
    return status;
}

// Print details about a loaded module
VOID H2PrintProcessModule(
    _In_ HANDLE Process,
    _In_ ULONG Index,
    _In_ PCWSTR BaseDllName,
    _In_ WORD BaseDllNameLength,
    _In_ PCWSTR FullDllName,
    _In_ WORD FullDllNameLength,
    _In_ ULONG_PTR BaseAddress,
    _In_ SIZE_T ImageSize,
    _In_ ULONG TimeDateStamp,
    _In_ LONGLONG LoadTime,
    _In_ LDR_DLL_LOAD_REASON LoadReason
)
{
    wprintf_s(L"[%u] ", Index);
    H2PrintProcessString(Process, BaseDllName, BaseDllNameLength);
    wprintf_s(L"\r\n  File name: ");
    H2PrintProcessString(Process, FullDllName, FullDllNameLength);
    wprintf_s(L"\r\n  File timestamp: ");
    H2PrintTimestamp(TimeDateStamp);
    wprintf_s(L"\r\n  Address range: 0x%zX-0x%zX (%zu KiB)", BaseAddress,
        BaseAddress + ImageSize - 1, ImageSize >> 10);
    wprintf_s(L"\r\n  Load time: ");
    H2PrintTimestamp(H2NativeTimeToUnixTime(LoadTime));
    wprintf_s(L"\r\n  Load reason: %s", H2LoadReasonToString(LoadReason));
    wprintf_s(L"\r\n\r\n");
}
