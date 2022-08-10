/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "unloaded_modules.h"
#include <time.h>
#include <wchar.h>

#define TIMESTAMP_STRING_LENGTH 20
#define NATIVE_SECOND 10000000

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