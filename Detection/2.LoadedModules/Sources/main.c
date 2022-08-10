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
#include <stdio.h>
#include <wchar.h>

int wmain(int argc, wchar_t* argv[])
{
    wprintf_s(L"A tool for inspecting loaded modules by Hunt & Hackett.\r\n\r\n");

    if (argc == 2)
    {
        ULONG_PTR pid = wcstoul(argv[1], NULL, 0);
        
        if (pid)
        {
            wprintf_s(L"Enumerating loaded modules of a process...\r\n\r\n");
            return H2EnumerateModulesProcess(pid);
        }
        else
        {
            wprintf_s(L"Reading a minidump...\r\n\r\n");
            return H2EnumerateModulesMiniDump(argv[1]);
        }
    }
    else if (argc >= 3)
    {
        wprintf_s(L"Creating a memory dump of a process..\r\n");
        return H2MakeMiniDump(
            wcstoul(argv[1], NULL, 0),
            argv[2],
            argc >= 4 ? wcstoul(argv[3], NULL, 0) : MiniDumpNormal
        );
    }

    wprintf_s(L"Usage:\r\n\r\n");
    wprintf_s(L"  LoadedModules.exe [PID] - enumerate loded modules for a process.\r\n");

    return STATUS_INVALID_PARAMETER;
}
