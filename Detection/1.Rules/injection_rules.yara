/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This Yara ruleset is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 * File version:
 *     1.1
 *
 */

import "pe"

// Private rules for grouping API calls //

private rule can_enumerate_processes
{
    strings:
        $function1 = "EnumProcesses" ascii wide fullword
        $function2 = "CreateToolhelp32Snapshot" ascii wide fullword
    
    condition:
        any of them
}

private rule can_open_processes
{
    strings:
        $function1 = "OpenProcess" ascii wide fullword
        $function2 = "NtOpenProcess" ascii wide fullword
        $function3 = "ZwOpenProcess" ascii wide fullword
        $function4 = "NtGetNextProcess" ascii wide fullword
        $function5 = "ZwGetNextProcess" ascii wide fullword
    
    condition:
        any of them
}

private rule can_create_processes
{
    strings:
        $function1 = "CreateProcessA" ascii wide fullword
        $function2 = "CreateProcessW" ascii wide fullword
        $function3 = "CreateProcessInternalA" ascii wide fullword
        $function4 = "CreateProcessInternalW" ascii wide fullword
        $function5 = "CreateProcessAsUserA" ascii wide fullword
        $function6 = "CreateProcessAsUserW" ascii wide fullword
        $function7 = "CreateProcessWithTokenW" ascii wide fullword
        $function8 = "CreateProcessWithLogonW" ascii wide fullword
        $function9 = "ShellExecuteA" ascii wide fullword
        $function10 = "ShellExecuteW" ascii wide fullword
        $function11 = "ShellExecuteExA" ascii wide fullword
        $function12 = "ShellExecuteExW" ascii wide fullword
        $function13 = "RtlCreateUserProcess" ascii wide fullword
        $function14 = "RtlCreateUserProcessEx" ascii wide fullword
        $function15 = "NtCreateUserProcess" ascii wide fullword
        $function16 = "ZwCreateUserProcess" ascii wide fullword
    
    condition:
        any of them
}

private rule can_modify_remote_memory
{
    strings:
        $function1 = "VirtualAllocEx" ascii wide fullword
        $function2 = "VirtualAllocExNuma" ascii wide fullword
        $function3 = "VirtualAlloc2" ascii wide fullword
        $function4 = "VirtualAlloc2FromApp" ascii wide fullword
        $function5 = "NtAllocateVirtualMemory" ascii wide fullword
        $function6 = "ZwAllocateVirtualMemory" ascii wide fullword
        $function7 = "NtAllocateVirtualMemoryEx" ascii wide fullword
        $function8 = "ZwAllocateVirtualMemoryEx" ascii wide fullword
        $function9 = "WriteProcessMemory" ascii wide fullword
        $function10 = "NtWriteVirtualMemory" ascii wide fullword
        $function11 = "ZwWriteVirtualMemory" ascii wide fullword
        $function12 = "VirtualProtectEx" ascii wide fullword
        $function13 = "NtProtectVirtualMemory" ascii wide fullword
        $function14 = "ZwProtectVirtualMemory" ascii wide fullword
        $function15 = "MapViewOfFile2" ascii wide fullword
        $function16 = "MapViewOfFileNuma2" ascii wide fullword
        $function17 = "MapViewOfFile3" ascii wide fullword
        $function18 = "MapViewOfFile3FromApp" ascii wide fullword
        $function19 = "NtMapViewOfSection" ascii wide fullword
        $function20 = "ZwMapViewOfSection" ascii wide fullword
        $function21 = "NtMapViewOfSectionEx" ascii wide fullword
        $function22 = "ZwMapViewOfSectionEx" ascii wide fullword
    
    condition:
        any of them
}

private rule can_create_remote_threads
{
    strings:
        $function1 = "CreateRemoteThread" ascii wide fullword
        $function2 = "CreateRemoteThreadEx" ascii wide fullword
        $function3 = "RtlCreateUserThread" ascii wide fullword
        $function4 = "NtCreateThreadEx" ascii wide fullword
        $function5 = "ZwCreateThreadEx" ascii wide fullword
    
    condition:
        any of them
}

private rule can_open_threads
{
    strings:
        $function1 = "OpenThread" ascii wide fullword
        $function2 = "NtOpenThread" ascii wide fullword
        $function3 = "ZwOpenThread" ascii wide fullword
        $function4 = "NtGetNextThread" ascii wide fullword
        $function5 = "ZwGetNextThread" ascii wide fullword
    
    condition:
        any of them
}

private rule can_queue_apcs
{
    strings:
        $function1 = "QueueUserAPC" ascii wide fullword
        $function2 = "QueueUserAPC2" ascii wide fullword
        $function3 = "NtQueueApcThread" ascii wide fullword
        $function4 = "ZwQueueApcThread" ascii wide fullword
        $function5 = "NtQueueApcThreadEx" ascii wide fullword
        $function6 = "ZwQueueApcThreadEx" ascii wide fullword
        $function7 = "RtlQueueApcWow64Thread" ascii wide fullword
    
    condition:
        any of them
}

private rule can_hijack_threads
{
    strings:
        $function1 = "SetThreadContext" ascii wide fullword
        $function2 = "Wow64SetThreadContext" ascii wide fullword
        $function3 = "NtSetContextThread" ascii wide fullword
        $function4 = "ZwSetContextThread" ascii wide fullword
        $function5 = "NtSetInformationThread" ascii wide fullword
        $function6 = "ZwSetInformationThread" ascii wide fullword
    
    condition:
        any of them
}

private rule can_create_processes_for_tampering
{
    strings:
        $function1 = "NtCreateProcess" ascii wide fullword
        $function2 = "ZwCreateProcess" ascii wide fullword
        $function3 = "NtCreateProcessEx" ascii wide fullword
        $function4 = "ZwCreateProcessEx" ascii wide fullword
    
    condition:
        any of them
}

private rule can_resume_execution
{
    strings:
        $function1 = "ResumeThread" ascii wide fullword
        $function2 = "NtResumeThread" ascii wide fullword
        $function3 = "ZwResumeThread" ascii wide fullword
        $function4 = "NtResumeProcess" ascii wide fullword
        $function5 = "ZwResumeProcess" ascii wide fullword
    
    condition:
        any of them
}

private rule can_create_image_sections
{
    strings:
        $function1 = "CreateFileMappingA" ascii wide fullword
        $function2 = "CreateFileMappingW" ascii wide fullword
        $function3 = "CreateFileMappingNumaA" ascii wide fullword
        $function4 = "CreateFileMappingNumaW" ascii wide fullword
        $function5 = "CreateFileMappingFromApp" ascii wide fullword
        $function6 = "CreateFileMapping2" ascii wide fullword
        $function7 = "NtCreateSection" ascii wide fullword
        $function8 = "ZwCreateSection" ascii wide fullword
        $function9 = "NtCreateSectionEx" ascii wide fullword
        $function10 = "ZwCreateSectionEx" ascii wide fullword
    
    condition:
        any of them
}

private rule can_unmap_image_sections
{
    strings:
        $function1 = "UnmapViewOfFile2" ascii wide fullword
        $function2 = "NtUnmapViewOfSection" ascii wide fullword
        $function3 = "ZwUnmapViewOfSection" ascii wide fullword
        $function4 = "NtUnmapViewOfSectionEx" ascii wide fullword
        $function5 = "ZwUnmapViewOfSectionEx" ascii wide fullword
    
    condition:
        any of them
}

private rule can_create_transactions
{
    strings:
        $function1 = "CreateTransaction" ascii wide fullword
        $function2 = "NtCreateTransaction" ascii wide fullword
        $function3 = "ZwCreateTransaction" ascii wide fullword
    
    condition:
        any of them
}

// Public rules for detection //

rule suspected_process_enumeration
{
    meta:
        author = "Hunt & Hackett"
        description = "Flags executables that might enumerate other process on the system."
        version = "1.1"
    condition:
        pe.is_pe and can_enumerate_processes
}

rule suspected_code_injection
{
    meta:
        author = "Hunt & Hackett"
        description = "Flags executables that might inject code into other processes."
        version = "1.1"
    condition:
        pe.is_pe and (can_open_processes or can_create_processes) and can_modify_remote_memory and
        (can_create_remote_threads or (can_open_threads and (can_queue_apcs or can_hijack_threads)))
}

rule suspected_process_tampering
{
    meta:
        author = "Hunt & Hackett"
        description = "Flags executables that might conceal code execution via using process tampering techniques."
        version = "1.1"
    condition:
        pe.is_pe and can_create_processes_for_tampering and can_modify_remote_memory
}

rule suspected_process_doppelganging
{
    meta:
        author = "Hunt & Hackett"
        description = "Flags executables that might perform Process Doppelganging."
        version = "1.1"
    condition:
        pe.is_pe and can_create_processes_for_tampering and can_create_transactions
}

rule suspected_process_hollowing
{
    meta:
        author = "Hunt & Hackett"
        description = "Flags executables that might perform Process Hollowing."
        version = "1.1"
    condition:
        pe.is_pe and (can_open_processes or can_create_processes) and
        can_create_image_sections and can_unmap_image_sections and
        (can_create_remote_threads or (can_hijack_threads and can_resume_execution))
}
