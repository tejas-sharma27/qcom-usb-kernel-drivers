/*++

Copyright (c) Qualcomm Inc. All rights reserved.

Module Name:
    FilterSecurity.h

Abstract:
    Header file for filter driver security descriptor handling.

--*/

#ifndef _FILTER_SECURITY_H_
#define _FILTER_SECURITY_H_

NTSTATUS
FilterValidateSecurityBuffer(
    _In_reads_bytes_opt_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN IsUserMode
);

NTSTATUS
FilterQuerySecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(*Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Inout_ PULONG Length,
    _In_ BOOLEAN IsUserMode
);

NTSTATUS
FilterSetSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_reads_bytes_(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Length,
    _In_ BOOLEAN IsUserMode
);

NTSTATUS
FilterDispatchQuerySecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS
FilterDispatchSetSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

#endif // _FILTER_SECURITY_H_