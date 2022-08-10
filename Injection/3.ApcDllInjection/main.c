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
#include <wchar.h>
#include <search.h>

#define HEADER_FIELD(NtHeaders, Field) (((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) \
	? ((PIMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field \
	: ((PIMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)

#define Wow64EncodeApcRoutine(ApcRoutine) \
    ((PVOID)((0 - ((LONG_PTR)(ApcRoutine))) << 2))

// Callback for binary search of exports
int __cdecl NameComparer(void* context, const void* key, const void* datum)
{
    return strcmp((PCSTR)key, RtlOffsetToPointer(context, *(PULONG)datum));
}

// Search for a specific function in the export directory of an image
_Success_(return)
BOOLEAN FindExportedRoutineRva(
    _In_ PVOID BaseOfImage,
    _In_ PCSTR RoutineName,
    _Out_ PULONG pRoutineRVA,
    _Out_opt_ PULONG pEntrypointRVA
)
{
    PIMAGE_NT_HEADERS ntHeader;
    ULONG exportDirectoryRva;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    PULONG names;
    PULONG functions;
    PUSHORT nameOrdinals;
    PULONG routineEntry;

    ntHeader = RtlImageNtHeader(BaseOfImage);

    if (!ntHeader)
        return FALSE;

    exportDirectoryRva = HEADER_FIELD(ntHeader, DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
    exportDirectory = RtlOffsetToPointer(BaseOfImage, exportDirectoryRva);
    names = RtlOffsetToPointer(BaseOfImage, exportDirectory->AddressOfNames);
    functions = RtlOffsetToPointer(BaseOfImage, exportDirectory->AddressOfFunctions);
    nameOrdinals = RtlOffsetToPointer(BaseOfImage, exportDirectory->AddressOfNameOrdinals);

    // Exported names are sorted; use binary search
    routineEntry = bsearch_s(
        RoutineName,
        names,
        exportDirectory->NumberOfNames,
        sizeof(ULONG),
        NameComparer,
        BaseOfImage
    );

    if (!routineEntry)
        return FALSE;

    *pRoutineRVA = functions[nameOrdinals[routineEntry - names]];

    if (pEntrypointRVA)
        *pEntrypointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;

    return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    HANDLE hKernel32Section = NULL;
    PVOID kernel32Base = NULL;
    HANDLE hSharedSection = NULL;

    wprintf_s(L"APC DLL injection demo by Hunt & Hackett.\r\n\r\n");

    if (argc < 2)
    {
        wprintf_s(L"Usage: ApcDllInjection.exe [PID] [filename]\r\n");
        status = STATUS_INVALID_PARAMETER;
        goto CLEANUP;
    }

    // Make the filename absolute
    WCHAR filenameBuffer[MAX_PATH];
    SIZE_T filenameSize;
    memset(filenameBuffer, 0, sizeof(filenameBuffer));

    status = RtlGetFullPathName_UEx(
        argv[2],
        sizeof(filenameBuffer),
        filenameBuffer,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"RtlGetFullPathName_UEx: %x\r\n", status);
        goto CLEANUP;
    }

    filenameSize = wcslen(filenameBuffer) * sizeof(WCHAR) + sizeof(UNICODE_NULL);
    wprintf_s(L"Injecting file: %s\r\n\r\n", (PWSTR)filenameBuffer);

    // Open the target process
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttr;

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)wcstoul(argv[1], NULL, 0);
    clientId.UniqueThread = 0;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = NtOpenProcess(
        &hProcess,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
        &objAttr,
        &clientId
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtOpenProcess: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine if the target is 32-bit and is running under WoW64
    ULONG_PTR wow64Peb;

    status = NtQueryInformationProcess(
        hProcess,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQueryInformationProcess: %x\r\n", status);
        goto CLEANUP;
    }

#ifndef _WIN64
    if (!wow64Peb)
    {
        wprintf_s(L"Cannot inject from a 32-bit to a 64-bit process. \
            Please use a 64-bit version of the tool instead.");
        status = STATUS_WOW_ASSERTION;
        goto CLEANUP;
    }
#endif

    // Open kernel32.dll section of the correct bitness
    UNICODE_STRING kernel32Name;

    if (wow64Peb)
        RtlInitUnicodeString(&kernel32Name, L"\\KnownDlls32\\kernel32.dll");
    else
        RtlInitUnicodeString(&kernel32Name, L"\\KnownDlls\\kernel32.dll");

    InitializeObjectAttributes(&objAttr, &kernel32Name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenSection(
        &hKernel32Section,
        SECTION_MAP_READ | SECTION_QUERY,
        &objAttr
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtOpenSection for kernel32: %x\r\n", status);
        goto CLEANUP;
    }

    // Determine its system-wide address
    SECTION_IMAGE_INFORMATION sectionInfo;

    status = NtQuerySection(
        hKernel32Section,
        SectionImageInformation,
        &sectionInfo,
        sizeof(sectionInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtQuerySection on kernel32: %x\r\n", status);
        goto CLEANUP;
    }

    // Map kernel32.dll for parsing
    SIZE_T kernel32Size;
    kernel32Size = 0;

    status = NtMapViewOfSection(
        hKernel32Section,
        NtCurrentProcess(),
        &kernel32Base,
        0,
        0,
        NULL,
        &kernel32Size,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    NtClose(hKernel32Section);
    hKernel32Section = NULL;

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtMapViewOfSection for kernel32: %x\r\n", status);
        goto CLEANUP;
    }

    // Find LoadLibrary
    ULONG loadLibraryRVA;
    ULONG entrypointRVA;

    if (!FindExportedRoutineRva(
        kernel32Base,
        "LoadLibraryW",
        &loadLibraryRVA,
        &entrypointRVA
    ))
    {
        wprintf_s(L"Cannot locate LoadLibraryW in kernel32.dll\r\n");
        status = STATUS_ENTRYPOINT_NOT_FOUND;
        goto CLEANUP;
    }

    NtUnmapViewOfSection(NtCurrentProcess(), kernel32Base);
    kernel32Base = NULL;

    // Create a section for sharing with the target
    LARGE_INTEGER sharedMemSize;
    sharedMemSize.QuadPart = filenameSize;

    status = NtCreateSection(
        &hSharedSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sharedMemSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtCreateSection for shared memory: %x\r\n", status);
        goto CLEANUP;
    }

    // Map the shared memory locally
    PVOID localSharedMemory;
    SIZE_T localSharedMemSize;
    localSharedMemory = NULL;
    localSharedMemSize = 0;

    status = NtMapViewOfSection(
        hSharedSection,
        NtCurrentProcess(),
        &localSharedMemory,
        0,
        0,
        NULL,
        &localSharedMemSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtMapViewOfSection for shared memory (locally): %x\r\n", status);
        goto CLEANUP;
    }

    // Copy the filename onto the shared memory
    memcpy_s(localSharedMemory, localSharedMemSize, filenameBuffer, filenameSize);
    NtUnmapViewOfSection(NtCurrentProcess(), localSharedMemory);
    localSharedMemory = NULL;

    // Map the shared memory remotely
    PVOID remoteSharedMemory;
    SIZE_T remoteSharedMemSize;
    remoteSharedMemory = NULL;
    remoteSharedMemSize = 0;

    status = NtMapViewOfSection(
        hSharedSection,
        hProcess,
        &remoteSharedMemory,
        0,
        0,
        NULL,
        &remoteSharedMemSize,
        ViewUnmap,
        0,
        PAGE_READONLY
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"NtMapViewOfSection for shared memory (remotely): %x\r\n", status);
        goto CLEANUP;
    }

    NtClose(hSharedSection);
    hSharedSection = NULL;

    // Prepare parameters for queueing APCs
    ULONG_PTR apcRoutine;
    apcRoutine = (ULONG_PTR)sectionInfo.TransferAddress - entrypointRVA + loadLibraryRVA;

    if (wow64Peb)
    {
        // Encode the pointer the same way RtlQueueApcWow64Thread does
        apcRoutine = Wow64EncodeApcRoutine(apcRoutine);
    }

    HANDLE apcFlags;
    apcFlags = 0;

    // Use special user APCs when supported (Windows 10 RS5+ / 10.0.17763+)
    if (
        RtlGetCurrentPeb()->OSMajorVersion > 10 ||
        (RtlGetCurrentPeb()->OSMajorVersion == 10 &&
            (RtlGetCurrentPeb()->OSMinorVersion > 0 ||
                (RtlGetCurrentPeb()->OSMinorVersion == 0 &&
                    RtlGetCurrentPeb()->OSBuildNumber >= 17763)))
        )
    {
        apcFlags = APC_FORCE_THREAD_SIGNAL;
        wprintf_s(L"Using special user APCs.\r\n");
    }

    // Enumerate threads and queue LoadLibrary APCs on them
    ULONG queuedCount;
    HANDLE hThread;
    LPCWSTR lastCall;

    queuedCount = 0;
    hThread = NULL;

    while (TRUE)
    {
        HANDLE hLastThread;        
        hLastThread = hThread;

        lastCall = L"NtGetNextThread";
        status = NtGetNextThread(
            hProcess,
            hLastThread,
            THREAD_SET_CONTEXT,
            0,
            0,
            &hThread
        );

        if (hLastThread)
        {
            NtClose(hLastThread);
            hLastThread = NULL;
        }

        if (!NT_SUCCESS(status))
            break;

        lastCall = L"NtQueueApcThreadEx"; 
        status = NtQueueApcThreadEx(
            hThread,
            apcFlags,
            (PVOID)apcRoutine,
            remoteSharedMemory,
            NULL,
            NULL
        );

        if (NT_SUCCESS(status))
            queuedCount++;
    }

    if (queuedCount > 0)
    {
        wprintf_s(L"Successfully queued %d APCs.\r\n", queuedCount);
        status = STATUS_SUCCESS;
    }
    else
    {
        wprintf_s(L"Failed queuing APCs; %s: %x.\r\n", lastCall, status);
    }    

CLEANUP:

    if (hKernel32Section)
        NtClose(hKernel32Section);

    if (kernel32Base)
        NtUnmapViewOfSection(NtCurrentProcess(), kernel32Base);

    if (hSharedSection)
        NtClose(hSharedSection);

    if (hProcess)
        NtClose(hProcess);

    return status;
}
