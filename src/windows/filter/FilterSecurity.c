/*++

Copyright (c) Qualcomm Inc. All rights reserved.

Module Name:
    FilterSecurity.c

Abstract:
    Security descriptor handling for filter driver to pass
    DF - Fuzz Query and Set Security Test (Reliability).

--*/

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "qcfilter.h"
#include "FilterSecurity.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FilterQuerySecurity)
#pragma alloc_text(PAGE, FilterSetSecurity)
#pragma alloc_text(PAGE, FilterValidateSecurityBuffer)
#endif

#define MAX_SECURITY_DESCRIPTOR_SIZE (64 * 1024)
#define MIN_SECURITY_DESCRIPTOR_SIZE sizeof(SECURITY_DESCRIPTOR)

/*++

Routine Description:
    Validates security buffer for filter driver operations.

Arguments:
    Buffer - Buffer pointer
    BufferLength - Buffer length
    IsWrite - TRUE for write access
    IsUserMode - TRUE if user mode buffer

Return Value:
    NTSTATUS code

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
FilterValidateSecurityBuffer(
    _In_reads_bytes_opt_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN IsUserMode
)
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    //
    // NULL buffer with zero length is valid
    //
    if (Buffer == NULL)
    {
        if (BufferLength == 0)
        {
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check maximum size
    //
    if (BufferLength > MAX_SECURITY_DESCRIPTOR_SIZE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate user mode buffers with SEH
    //
    if (IsUserMode)
    {
        __try
        {
            if (IsWrite)
            {
                ProbeForWrite(Buffer, BufferLength, sizeof(UCHAR));
            }
            else
            {
                ProbeForRead(Buffer, BufferLength, sizeof(UCHAR));
            }

            //
            // Touch buffer boundaries
            //
            if (BufferLength > 0)
            {
                volatile UCHAR testByte;
                PUCHAR bufferBytes = (PUCHAR)Buffer;

                if (IsWrite)
                {
                    bufferBytes[0] = bufferBytes[0];
                    if (BufferLength > 1)
                    {
                        bufferBytes[BufferLength - 1] = bufferBytes[BufferLength - 1];
                    }
                }
                else
                {
                    testByte = bufferBytes[0];
                    if (BufferLength > 1)
                    {
                        testByte = bufferBytes[BufferLength - 1];
                    }
                    UNREFERENCED_PARAMETER(testByte);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    else
    {
        //
        // Validate kernel mode buffer
        //
        if (!MmIsAddressValid(Buffer))
        {
            return STATUS_ACCESS_VIOLATION;
        }

        if (BufferLength > 0)
        {
            PUCHAR endAddress = (PUCHAR)Buffer + BufferLength - 1;
            if (!MmIsAddressValid(endAddress))
            {
                return STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return STATUS_SUCCESS;
}

/*++

Routine Description:
    Query security descriptor for filter device.

Arguments:
    DeviceObject - Device object
    SecurityInformation - Security information requested
    SecurityDescriptor - Output buffer
    Length - Buffer length (in/out)
    IsUserMode - TRUE if user mode

Return Value:
    NTSTATUS code

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
FilterQuerySecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(*Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Inout_ PULONG Length,
    _In_ BOOLEAN IsUserMode
)
{
    NTSTATUS status;
    ULONG requiredLength = 0;
    PSECURITY_DESCRIPTOR deviceSecurityDescriptor = NULL;
    ULONG bufferLength;

    PAGED_CODE();

    //
    // Validate Length pointer
    //
    if (Length == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        bufferLength = *Length;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    //
    // Validate buffer
    //
    status = FilterValidateSecurityBuffer(
        SecurityDescriptor,
        bufferLength,
        TRUE,
        IsUserMode
    );

    if (!NT_SUCCESS(status))
    {
        if (SecurityDescriptor == NULL || bufferLength == 0)
        {
            requiredLength = sizeof(SECURITY_DESCRIPTOR) + 256;
            __try
            {
                *Length = requiredLength;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                return STATUS_ACCESS_VIOLATION;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }
    return status;
}

/*++

Routine Description:
    Dispatch routine for IRP_MJ_QUERY_SECURITY in filter driver.

Arguments:
    DeviceObject - Pointer to device object
    Irp - Pointer to I/O request packet

Return Value:
    NTSTATUS code

--*/
NTSTATUS
FilterDispatchQuerySecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    SECURITY_INFORMATION securityInformation;
    PSECURITY_DESCRIPTOR securityDescriptor;
    ULONG length;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    securityInformation = irpSp->Parameters.QuerySecurity.SecurityInformation;
    length = irpSp->Parameters.QuerySecurity.Length;
    securityDescriptor = (PSECURITY_DESCRIPTOR)Irp->UserBuffer;

    status = FilterQuerySecurity(
        DeviceObject,
        securityInformation,
        securityDescriptor,
        &length,
        Irp->RequestorMode == UserMode
    );

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? length : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

/*++

Routine Description:
    Dispatch routine for IRP_MJ_SET_SECURITY in filter driver.

Arguments:
    DeviceObject - Pointer to device object
    Irp - Pointer to I/O request packet

Return Value:
    NTSTATUS code

--*/
NTSTATUS
FilterDispatchSetSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    SECURITY_INFORMATION securityInformation;
    PSECURITY_DESCRIPTOR securityDescriptor;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    securityInformation = irpSp->Parameters.SetSecurity.SecurityInformation;
    securityDescriptor = (PSECURITY_DESCRIPTOR)irpSp->Parameters.SetSecurity.SecurityDescriptor;

    status = FilterSetSecurity(
        DeviceObject,
        securityInformation,
        securityDescriptor,
        sizeof(SECURITY_DESCRIPTOR),
        Irp->RequestorMode == UserMode
    );

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

    //
    // Get security descriptor
    //
    status = ObGetObjectSecurity(
        DeviceObject,
        &deviceSecurityDescriptor,
        &requiredLength
    );

    if (!NT_SUCCESS(status))
    {
        __try
        {
            *Length = requiredLength;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return status;
    }

    //
    // Check buffer size
    //
    if (bufferLength < requiredLength)
    {
        __try
        {
            *Length = requiredLength;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        ObReleaseObjectSecurity(deviceSecurityDescriptor, FALSE);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Copy security descriptor
    //
    __try
    {
        RtlCopyMemory(SecurityDescriptor, deviceSecurityDescriptor, requiredLength);
        *Length = requiredLength;
        status = STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_ACCESS_VIOLATION;
    }

    ObReleaseObjectSecurity(deviceSecurityDescriptor, FALSE);

    return status;
}

/*++

Routine Description:
    Set security descriptor for filter device.

Arguments:
    DeviceObject - Device object
    SecurityInformation - Security information to set
    SecurityDescriptor - Input buffer
    Length - Buffer length
    IsUserMode - TRUE if user mode

Return Value:
    NTSTATUS code

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
FilterSetSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_reads_bytes_(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Length,
    _In_ BOOLEAN IsUserMode
)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR capturedDescriptor = NULL;
    BOOLEAN isValid = FALSE;

    PAGED_CODE();

    //
    // Validate buffer
    //
    status = FilterValidateSecurityBuffer(
        SecurityDescriptor,
        Length,
        FALSE,
        IsUserMode
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //
    // Check for NULL or zero length
    //
    if (SecurityDescriptor == NULL || Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check minimum size
    //
    if (Length < MIN_SECURITY_DESCRIPTOR_SIZE)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Capture and validate security descriptor
    //
    __try
    {
        capturedDescriptor = ExAllocatePoolWithTag(
            PagedPool,
            Length,
            'cSrF'  // 'FrSc'
        );

        if (capturedDescriptor == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(capturedDescriptor, SecurityDescriptor, Length);

        isValid = RtlValidSecurityDescriptor(capturedDescriptor);

        if (!isValid)
        {
            status = STATUS_INVALID_SECURITY_DESCR;
            __leave;
        }

        status = ObSetSecurityObjectByPointer(
            DeviceObject,
            SecurityInformation,
            capturedDescriptor
        );
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_ACCESS_VIOLATION;
    }

    if (capturedDescriptor != NULL)
    {
        ExFreePoolWithTag(capturedDescriptor, 'cSrF');
    }

    return status;
}