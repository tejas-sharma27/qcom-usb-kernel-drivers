/*++

Copyright (c) Qualcomm Inc. All rights reserved.

Module Name:
    MPSecurity.h

Abstract:
    Header file for security descriptor handling in NDIS miniport driver.
    Provides declarations for DF - Fuzz Query and Set Security Test compliance.

--*/

#ifndef _MP_SECURITY_H_
#define _MP_SECURITY_H_

//
// Function prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPValidateSecurityBuffer(
    _In_reads_bytes_opt_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN IsUserMode
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPValidateSecurityInformation(
    _In_ SECURITY_INFORMATION SecurityInformation
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPQuerySecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(*Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Inout_ PULONG Length,
    _In_ BOOLEAN IsUserMode
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPSetSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_reads_bytes_(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Length,
    _In_ BOOLEAN IsUserMode
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPDispatchQuerySecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPDispatchSetSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

//
// Security validation macros
//

#define IS_VALID_SECURITY_INFO(info) \
    (MPValidateSecurityInformation(info) == STATUS_SUCCESS)

#define IS_VALID_SECURITY_BUFFER(buf, len, write, user) \
    (MPValidateSecurityBuffer(buf, len, write, user) == STATUS_SUCCESS)

//
// Security information type flags for validation
//

#define MP_SECURITY_ALL_VALID_FLAGS ( \
    OWNER_SECURITY_INFORMATION |      \
    GROUP_SECURITY_INFORMATION |      \
    DACL_SECURITY_INFORMATION |       \
    SACL_SECURITY_INFORMATION |       \
    LABEL_SECURITY_INFORMATION |      \
    ATTRIBUTE_SECURITY_INFORMATION |  \
    SCOPE_SECURITY_INFORMATION |      \
    PROCESS_TRUST_LABEL_SECURITY_INFORMATION | \
    ACCESS_FILTER_SECURITY_INFORMATION | \
    BACKUP_SECURITY_INFORMATION |     \
    PROTECTED_DACL_SECURITY_INFORMATION | \
    PROTECTED_SACL_SECURITY_INFORMATION | \
    UNPROTECTED_DACL_SECURITY_INFORMATION | \
    UNPROTECTED_SACL_SECURITY_INFORMATION)

//
// Buffer size limits
//

#define MP_MIN_SECURITY_DESCRIPTOR_SIZE sizeof(SECURITY_DESCRIPTOR)
#define MP_MAX_SECURITY_DESCRIPTOR_SIZE (64 * 1024)

#endif // _MP_SECURITY_H_