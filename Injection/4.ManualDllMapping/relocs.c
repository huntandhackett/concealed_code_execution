/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "manual_mapping.h"

typedef struct _IMAGE_BASE_RELOCATION_ENTRY
{
    USHORT Offset : 12;
    USHORT Type : 4;
} IMAGE_BASE_RELOCATION_ENTRY, *PIMAGE_BASE_RELOCATION_ENTRY;

NTSTATUS H2ApplyRelocations(
    _In_ PVOID ImageAddress,
    _In_ ULONG64 ImageSize,
    _In_ ULONG64 NewImageBase
)
{
    NTSTATUS status;
    PIMAGE_NT_HEADERS imageNtHeader;

    status = RtlImageNtHeaderEx(
        0,
        ImageAddress,
        ImageSize,
        &imageNtHeader
    );

    if (!NT_SUCCESS(status))
        return status;

    ULONG64 relocationDelta;
    IMAGE_DATA_DIRECTORY relocDirectory;
    relocationDelta = (ULONG64)NewImageBase - imageNtHeader->OptionalHeader.ImageBase;
    relocDirectory = HEADER_FIELD(imageNtHeader, DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

    if (relocationDelta == 0)
        return STATUS_SUCCESS;

    if (imageNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        return STATUS_ILLEGAL_DLL_RELOCATION;

    if (relocDirectory.Size == 0)
        return STATUS_SUCCESS;

    PIMAGE_BASE_RELOCATION relocEntry;
    PCHAR relocStop;

    // Adjust the ImageBase field in the headers
    imageNtHeader->OptionalHeader.ImageBase = NewImageBase;

    relocEntry = RtlOffsetToPointer(ImageAddress, relocDirectory.VirtualAddress);
    relocStop = RtlOffsetToPointer(relocEntry, relocDirectory.Size);

    // Process relocations page-by-page
    for (
        ;
        relocEntry <= relocStop - sizeof(IMAGE_BASE_RELOCATION);
        relocEntry = RtlOffsetToPointer(relocEntry, relocEntry->SizeOfBlock)
        )
    {
        PIMAGE_BASE_RELOCATION_ENTRY typeOffsets;
        PVOID targetPage;

        targetPage = RtlOffsetToPointer(ImageAddress, relocEntry->VirtualAddress);

        for (
            typeOffsets = RtlOffsetToPointer(relocEntry, sizeof(IMAGE_BASE_RELOCATION));
            typeOffsets < RtlOffsetToPointer(relocEntry, relocEntry->SizeOfBlock);
            typeOffsets++
            )
        {
            PVOID target;
            target = RtlOffsetToPointer(targetPage, typeOffsets->Offset);

            // Adjust the target
            switch (typeOffsets->Type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break; // Nothing to do

            case IMAGE_REL_BASED_HIGH:
                *(PWORD)target = *(PWORD)target + (WORD)(relocationDelta >> 16);
                break;

            case IMAGE_REL_BASED_LOW:
                *(PWORD)target = *(PWORD)target + (WORD)relocationDelta;
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                *(PULONG)target = *(PULONG)target + (ULONG)relocationDelta;
                break;

            case IMAGE_REL_BASED_DIR64:
                *(PULONG64)target = *(PULONG64)target + (ULONG64)relocationDelta;
                break;

            default:
                return STATUS_NOT_SUPPORTED;
            }
        }
    }

    return STATUS_SUCCESS;
}