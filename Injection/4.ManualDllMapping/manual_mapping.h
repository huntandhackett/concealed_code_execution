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

#define HEADER_FIELD(NtHeaders, Field) (((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) \
	? ((PIMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field \
	: ((PIMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)

/* mapping.c */

// Map a file into the current process for reading
NTSTATUS H2MapReadOnlyFile(
	_In_ PUNICODE_STRING FileName,
	_In_ ULONG AllocationAttributes,
	_Out_ PVOID *Base,
	_Out_ SIZE_T *Size,
	_Out_opt_ PCWSTR *LastCall
);

// Determine if the image is suitable for mapping
NTSTATUS H2IsImageCompatible(
	_In_ PIMAGE_NT_HEADERS ImageNtHeaders,
	_In_ BOOLEAN TargetIsWoW64
);

// Map a shared memory region with the target and deploy a PE image from the data
NTSTATUS H2MapImagesFromData(
	_In_ PVOID Data,
	_In_ SIZE_T DataSize,
	_In_ HANDLE hProcess,
	_Out_ PVOID *LocalImageAddress,
	_Out_ PVOID *RemoteImageAddress,
	_Out_ SIZE_T *ImageSize,
	_Out_opt_ PCWSTR *LastCall
);

/* export.c */

// Search for a specific function in the export directory of an image
NTSTATUS H2FindExportedRoutine(
	_In_ PVOID ImageAddress,
	_In_ ULONG64 ImageSize,
	_In_ PCSTR RoutineNames,
	_Out_ PULONG RoutineRVAs,
	_Out_opt_ PULONG pEntrypointRVA
);

// Find a function in a Known DLL
NTSTATUS H2FindKnownDllExport(
    _In_ PCWSTR KnownDllSectionName,
    _In_ PCSTR FunctionName,
    _Out_ PVOID *FunctionAddress,
    _Out_opt_ PCWSTR *LastCall
);

NTSTATUS H2ResoleImports(
	_In_ HANDLE hProcess,
	_In_ PVOID LocalAddress,
	_In_ SIZE_T ImageSize
);

/* relocs.c */

// Relocate image (mapped as RW) to a new address
NTSTATUS H2ApplyRelocations(
	_In_ PVOID ImageAddress,
	_In_ ULONG64 ImageSize,
	_In_ ULONG64 NewImageBase
);