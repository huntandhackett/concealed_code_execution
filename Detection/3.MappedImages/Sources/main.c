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
#include <wchar.h>

int wmain(int argc, wchar_t* argv[])
{
    ULONG_PTR pid;
    wprintf_s(L"A tool for enumerating mapped images by Hunt & Hackett.\r\n\r\n");    

    if ((argc < 2) || !(pid = wcstoul(argv[1], NULL, 0)))
    {
        wprintf_s(L"Usage:\r\n");
        wprintf_s(L"  MappedImages.exe [PID]\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    return H2PrintMappedImagesProcessID((HANDLE)pid);
}
