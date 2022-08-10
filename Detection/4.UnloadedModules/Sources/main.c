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
#include <stdio.h>
#include <wchar.h>
#include <search.h>

int wmain(int argc, wchar_t* argv[])
{
    wprintf_s(L"A tool for inspecting unloaded modules by Hunt & Hackett.\r\n\r\n");

    if (argc == 2)
    {
        ULONG_PTR pid = wcstoul(argv[1], NULL, 0);

        if (pid)
        {
            wprintf_s(L"Enumerating unloaded modules of a process...\r\n\r\n");
            return H2EnumerateUnloadedModulesProcess(pid);
        }
        else
        {
            wprintf_s(L"Reading a minidump...\r\n\r\n");
            return H2EnumerateUnloadedModulesMiniDump(argv[1]);
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
    wprintf_s(L"1. UnloadedModules.exe [PID] - enumerate unloded modules for a process.\r\n");
    wprintf_s(L"2. UnloadedModules.exe [filename] - read unloaded modules from a minidump.\r\n");
    wprintf_s(L"3. UnloadedModules.exe [PID] [filname] [[type]] - save a minidump of a process.\r\n");
    wprintf_s(L"   Where type is an optional value for MINIDUMP_TYPE (see Microsoft SDK).\r\n\r\n");

    return STATUS_INVALID_PARAMETER;

    
}
