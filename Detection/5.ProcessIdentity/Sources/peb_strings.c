/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "process_identity.h"

// Read a UNICODE_STRING from a process of the same bitness
NTSTATUS H2ReadStringProcess(
	_In_ HANDLE Process,
	_In_ PUNICODE_STRING RemoteString,
	_Out_ PUNICODE_STRING *String,
	_In_opt_ ULONG_PTR NormalizeRelativeTo
)
{
	NTSTATUS status;
	UNICODE_STRING stringDefinition;
	PUNICODE_STRING buffer;
	
	// Read the string definition
	status = NtReadVirtualMemory(
		Process,
		RemoteString,
		&stringDefinition,
		sizeof(stringDefinition),
		NULL
	);

	if (!NT_SUCCESS(status))
		return status;

	// Prepare a local buffer
	status = H2Allocate(
		sizeof(UNICODE_STRING) + stringDefinition.Length + sizeof(UNICODE_NULL),
		&buffer,
		HEAP_ZERO_MEMORY
	);

	if (!NT_SUCCESS(status))
		return status;

	buffer->Length = stringDefinition.Length;
	buffer->MaximumLength = buffer->Length + sizeof(UNICODE_NULL);
	buffer->Buffer = (PVOID)&buffer[1];

	if (NormalizeRelativeTo)
	{
		// The buffer stores an offset; make it absolute
		stringDefinition.Buffer = (PWCH)RtlOffsetToPointer(NormalizeRelativeTo, stringDefinition.Buffer);
	}

	// Read the content
	status = NtReadVirtualMemory(
		Process,
		stringDefinition.Buffer,
		buffer->Buffer,
		buffer->Length,
		NULL
	);

	if (NT_SUCCESS(status))
		*String = buffer;
	else
		H2Free(buffer);
	
	return status;
}

// Print a UNICODE_STRING
VOID H2PrintStringProcess(
	_In_ HANDLE Process,
	_In_ PUNICODE_STRING RemoteString,
	_In_opt_ PCWSTR Comment,
	_In_opt_ ULONG_PTR NormalizeRelativeTo
)
{
	NTSTATUS status;
	PUNICODE_STRING buffer;

	status = H2ReadStringProcess(Process, RemoteString, &buffer, NormalizeRelativeTo);

	if (Comment)
		wprintf_s(L"%s:\r\n  ", Comment);

	if (NT_SUCCESS(status))
	{
		wprintf_s(L"%wZ\r\n\r\n", buffer);
		H2Free(buffer);
	}
	else
	{
		H2PrintStatus(status);
	}
}

#ifdef _WIN64
// Read a UNICODE_STRING32 from a process running under WoW64
NTSTATUS H2ReadStringProcess32(
	_In_ HANDLE Process,
	_In_ PUNICODE_STRING32 RemoteString,
	_Out_ PUNICODE_STRING* String,
	_In_opt_ ULONG NormalizeRelativeTo
)
{
	NTSTATUS status;
	UNICODE_STRING32 stringDefinition;
	PUNICODE_STRING buffer;

	// Read the string definition
	status = NtReadVirtualMemory(
		Process,
		RemoteString,
		&stringDefinition,
		sizeof(stringDefinition),
		NULL
	);

	if (!NT_SUCCESS(status))
		return status;

	// Prepare a local buffer
	status = H2Allocate(
		sizeof(UNICODE_STRING) + stringDefinition.Length + sizeof(UNICODE_NULL),
		&buffer,
		HEAP_ZERO_MEMORY
	);

	if (!NT_SUCCESS(status))
		return status;

	buffer->Length = stringDefinition.Length;
	buffer->MaximumLength = buffer->Length + sizeof(UNICODE_NULL);
	buffer->Buffer = (PVOID)&buffer[1];

	if (NormalizeRelativeTo)
	{
		// The buffer stores an offset; make it absolute
		stringDefinition.Buffer += NormalizeRelativeTo;
	}

	// Read the content
	status = NtReadVirtualMemory(
		Process,
		(PVOID)(ULONG_PTR)stringDefinition.Buffer,
		buffer->Buffer,
		buffer->Length,
		NULL
	);

	if (NT_SUCCESS(status))
		*String = buffer;
	else
		H2Free(buffer);

	return status;
}

// Print a UNICODE_STRING32
VOID H2PrintStringProcess32(
	_In_ HANDLE Process,
	_In_ PUNICODE_STRING32 RemoteString,
	_In_opt_ PCWSTR Comment,
	_In_opt_ ULONG NormalizeRelativeTo
)
{
	NTSTATUS status;
	PUNICODE_STRING buffer;

	status = H2ReadStringProcess32(Process, RemoteString, &buffer, NormalizeRelativeTo);

	if (Comment)
		wprintf_s(L"%s:\r\n  ", Comment);

	if (NT_SUCCESS(status))
	{
		wprintf_s(L"%wZ\r\n\r\n", buffer);
		H2Free(buffer);
	}
	else
	{
		H2PrintStatus(status);
	}
}
#endif // _WIN64

// Print strings from remote PEB
NTSTATUS H2PrintPebStringsProcess(
	_In_ HANDLE Process
)
{
	NTSTATUS status;
	PPEB32 wow64Peb;

	// Query WoW64 PEB location first
	status = NtQueryInformationProcess(
		Process,
		ProcessWow64Information,
		&wow64Peb,
		sizeof(wow64Peb),
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		wprintf_s(L"Cannot determine if the target runs under WoW64: 0x%X\r\n", status);
		return status;
	}

#ifdef _WIN64
	if (wow64Peb)
	{
		WOW64_POINTER(PRTL_USER_PROCESS_PARAMETERS32) procParams32;
		PRTL_USER_PROCESS_PARAMETERS32 procParams;
		ULONG flags;
		ULONG normalizeRelativeTo;

		// Read pointer to WoW64 process parameters
		status = NtReadVirtualMemory(
			Process,
			&wow64Peb->ProcessParameters,
			&procParams32,
			sizeof(procParams32),
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			wprintf_s(L"Cannot read pointer to WoW64 process parameters: 0x%X\r\n", status);
			return status;
		}

		procParams = (PVOID)(ULONG_PTR)procParams32;

		// We first need to read the flags to determine whether the process
		// parameters are normalized or not.
		status = NtReadVirtualMemory(
			Process,
			&procParams->Flags,
			&flags,
			sizeof(flags),
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			wprintf_s(L"Cannot read WoW64 process parameter flags: 0x%X\r\n", status);
			return status;
		}

		if (flags & RTL_USER_PROC_PARAMS_NORMALIZED)
		{
			// The strings use absolute pointers, no need to normalize them
			normalizeRelativeTo = 0;
		}
		else
		{
			// The strings store offsets from the start of process parameters
			normalizeRelativeTo = procParams32;
		}

		// Read and print strings
		H2PrintStringProcess32(Process, &procParams->ImagePathName, L"Image name (WoW64 PEB)", normalizeRelativeTo);
		H2PrintStringProcess32(Process, &procParams->CommandLine, L"Command line (WoW64 PEB)", normalizeRelativeTo);
	}
#endif

	PROCESS_BASIC_INFORMATION basicInfo;
	PRTL_USER_PROCESS_PARAMETERS procParams;
	ULONG flags;
	ULONG_PTR normalizeRelativeTo;

	// Determine native PEB location
	status = NtQueryInformationProcess(
		Process,
		ProcessBasicInformation,
		&basicInfo,
		sizeof(basicInfo),
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		wprintf_s(L"Cannot determine native PEB location: 0x%X\r\n", status);
		return status;
	}

	// Read pointer to process parameters
	status = NtReadVirtualMemory(
		Process,
		&basicInfo.PebBaseAddress->ProcessParameters,
		&procParams,
		sizeof(procParams),
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		wprintf_s(L"Cannot read pointer to process parameters: 0x%X\r\n", status);
		return status;
	}

	// We first need to read the flags to determine whether the process
	// parameters are normalized or not.
	status = NtReadVirtualMemory(
		Process,
		&procParams->Flags,
		&flags,
		sizeof(flags),
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		wprintf_s(L"Cannot read process parameter flags: 0x%X\r\n", status);
		return status;
	}

	if (flags & RTL_USER_PROC_PARAMS_NORMALIZED)
	{
		// The strings use absolute pointers, no need to normalize them
		normalizeRelativeTo = 0;
	}
	else
	{
		// The strings store offsets from the start of process parameters
		normalizeRelativeTo = (ULONG_PTR)procParams;
	}

	// Read and print strings
	H2PrintStringProcess(Process, &procParams->ImagePathName, L"Image name (PEB)", normalizeRelativeTo);
	H2PrintStringProcess(Process, &procParams->CommandLine, L"Command line (PEB)", normalizeRelativeTo);
}
