/*++

Copyright (c) Qualcomm Inc. All rights reserved.

Module Name:
    MPSecurity.c

Abstract:
    This module implements robust security descriptor handling for NDIS miniport driver
    to pass DF - Fuzz Query and Set Security Test (Reliability).
    
    Handles:
    - Query and Set Security operations with proper validation
    - Buffer length validation (0 to maximum)
    - Invalid buffer pointer protection
    - All security information types (OWNER, GROUP, DACL, SACL)
    - Memory protection flags
    - Structured Exception Handling (SEH)

--*/

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "MPMain.h"
#include "MPSecurity.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MPQuerySecurity)
#pragma alloc_text(PAGE, MPSetSecurity)
#pragma alloc_text(PAGE, MPValidateSecurityBuffer)
#pragma alloc_text(PAGE, MPValidateSecurityInformation)
#endif

//
// Maximum security descriptor size (64KB is reasonable limit)
//
#define MAX_SECURITY_DESCRIPTOR_SIZE    (64 * 1024)

//
// Minimum security descriptor size
//
#define MIN_SECURITY_DESCRIPTOR_SIZE    sizeof(SECURITY_DESCRIPTOR)

//
// Valid security information flags mask
//
#define VALID_SECURITY_INFORMATION_MASK ( \
    OWNER_SECURITY_INFORMATION |          \
    GROUP_SECURITY_INFORMATION |          \
    DACL_SECURITY_INFORMATION |           \
    SACL_SECURITY_INFORMATION |           \
    LABEL_SECURITY_INFORMATION |          \
    ATTRIBUTE_SECURITY_INFORMATION |      \
    SCOPE_SECURITY_INFORMATION |          \
    PROCESS_TRUST_LABEL_SECURITY_INFORMATION | \
    ACCESS_FILTER_SECURITY_INFORMATION |  \
    BACKUP_SECURITY_INFORMATION |         \
    PROTECTED_DACL_SECURITY_INFORMATION | \
    PROTECTED_SACL_SECURITY_INFORMATION | \
    UNPROTECTED_DACL_SECURITY_INFORMATION | \
    UNPROTECTED_SACL_SECURITY_INFORMATION)

/*++

Routine Description:
    Validates security buffer pointer and length with comprehensive checks
    to handle fuzz testing scenarios.

Arguments:
    Buffer - Pointer to security descriptor buffer
    BufferLength - Length of the buffer
    RequiredAccess - Required access (read or write)
    IsUserMode - TRUE if buffer is from user mode

Return Value:
    STATUS_SUCCESS if valid
    STATUS_INVALID_PARAMETER if invalid
    STATUS_ACCESS_VIOLATION if buffer is inaccessible
    STATUS_BUFFER_TOO_SMALL if buffer is too small

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPValidateSecurityBuffer(
    _In_reads_bytes_opt_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN IsUserMode
)
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    //
    // Handle NULL buffer cases
    //
    if (Buffer == NULL)
    {
        //
        // NULL buffer with zero length is valid for query size operations
        //
        if (BufferLength == 0)
        {
            return STATUS_SUCCESS;
        }
        
        //
        // NULL buffer with non-zero length is invalid
        //
        DbgPrint("MPValidateSecurityBuffer: NULL buffer with non-zero length %lu\n", 
                 BufferLength);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate buffer length is within reasonable bounds
    //
    if (BufferLength > MAX_SECURITY_DESCRIPTOR_SIZE)
    {
        DbgPrint("MPValidateSecurityBuffer: Buffer length %lu exceeds maximum %lu\n",
                 BufferLength, MAX_SECURITY_DESCRIPTOR_SIZE);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // For user-mode buffers, use structured exception handling
    //
    if (IsUserMode)
    {
        __try
        {
            //
            // Probe the buffer for appropriate access
            //
            if (IsWrite)
            {
                ProbeForWrite(Buffer, BufferLength, sizeof(UCHAR));
            }
            else
            {
                ProbeForRead(Buffer, BufferLength, sizeof(UCHAR));
            }

            //
            // Additional validation: touch first and last byte
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
            status = GetExceptionCode();
            DbgPrint("MPValidateSecurityBuffer: Exception 0x%08X accessing buffer\n", 
                     status);
            return STATUS_ACCESS_VIOLATION;
        }
    }
    else
    {
        //
        // For kernel-mode buffers, validate address range
        //
        if (!MmIsAddressValid(Buffer))
        {
            DbgPrint("MPValidateSecurityBuffer: Invalid kernel buffer address\n");
            return STATUS_ACCESS_VIOLATION;
        }

        //
        // Check if buffer end is valid
        //
        if (BufferLength > 0)
        {
            PUCHAR endAddress = (PUCHAR)Buffer + BufferLength - 1;
            if (!MmIsAddressValid(endAddress))
            {
                DbgPrint("MPValidateSecurityBuffer: Invalid buffer end address\n");
                return STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return STATUS_SUCCESS;
}

/*++

Routine Description:
    Validates security information flags to ensure only valid combinations
    are specified.

Arguments:
    SecurityInformation - Security information flags to validate

Return Value:
    STATUS_SUCCESS if valid
    STATUS_INVALID_PARAMETER if invalid

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPValidateSecurityInformation(
    _In_ SECURITY_INFORMATION SecurityInformation
)
{
    PAGED_CODE();

    //
    // Allow zero security information (used in fuzz testing)
    //
    if (SecurityInformation == 0)
    {
        return STATUS_SUCCESS;
    }

    //
    // Check for invalid flags
    //
    if ((SecurityInformation & ~VALID_SECURITY_INFORMATION_MASK) != 0)
    {
        DbgPrint("MPValidateSecurityInformation: Invalid flags 0x%08X\n",
                 SecurityInformation);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate SACL access requires appropriate privilege
    // (This is informational - actual privilege check done by system)
    //
    if ((SecurityInformation & SACL_SECURITY_INFORMATION) != 0)
    {
        DbgPrint("MPValidateSecurityInformation: SACL access requested\n");
    }

    return STATUS_SUCCESS;
}

/*++

Routine Description:
    Handles query security descriptor operations with comprehensive
    validation and error handling for fuzz testing.

Arguments:
    DeviceObject - Pointer to device object
    SecurityInformation - Requested security information
    SecurityDescriptor - Output buffer for security descriptor
    Length - Pointer to buffer length (in/out)
    IsUserMode - TRUE if called from user mode

Return Value:
    NTSTATUS code

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPQuerySecurity(
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

    DbgPrint("MPQuerySecurity: SecurityInfo=0x%08X, Buffer=%p, Length=%lu\n",
             SecurityInformation, SecurityDescriptor, 
             Length ? *Length : 0);

    //
    // Validate Length pointer
    //
    if (Length == NULL)
    {
        DbgPrint("MPQuerySecurity: NULL Length pointer\n");
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Capture buffer length
    //
    __try
    {
        bufferLength = *Length;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("MPQuerySecurity: Exception accessing Length pointer\n");
        return STATUS_ACCESS_VIOLATION;
    }

    //
    // Validate security information flags
    //
    status = MPValidateSecurityInformation(SecurityInformation);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //
    // Validate output buffer
    //
    status = MPValidateSecurityBuffer(
        SecurityDescriptor,
        bufferLength,
        TRUE,  // Write access
        IsUserMode
    );
    if (!NT_SUCCESS(status))
    {
        //
        // For NULL buffer or zero length, return required size
        //
        if (status == STATUS_INVALID_PARAMETER && 
            (SecurityDescriptor == NULL || bufferLength == 0))
        {
            //
            // Calculate required size
            //
            requiredLength = sizeof(SECURITY_DESCRIPTOR) + 256; // Reasonable estimate
            
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

    //
    // Get device security descriptor
    //
    status = ObGetObjectSecurity(
        DeviceObject,
        &deviceSecurityDescriptor,
        &requiredLength
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("MPQuerySecurity: ObGetObjectSecurity failed 0x%08X\n", status);
        
        __try
        {
            *Length = requiredLength;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            // Ignore exception on output
        }
        
        return status;
    }

    //
    // Check if buffer is large enough
    //
    if (bufferLength < requiredLength)
    {
        DbgPrint("MPQuerySecurity: Buffer too small: %lu < %lu\n",
                 bufferLength, requiredLength);
        
        __try
        {
            *Length = requiredLength;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            // Ignore exception on output
        }
        
        ObReleaseObjectSecurity(deviceSecurityDescriptor, FALSE);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Copy security descriptor to output buffer with SEH protection
    //
    __try
    {
        RtlCopyMemory(
            SecurityDescriptor,
            deviceSecurityDescriptor,
            requiredLength
        );
        
        *Length = requiredLength;
        status = STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        DbgPrint("MPQuerySecurity: Exception 0x%08X copying security descriptor\n",
                 status);
        status = STATUS_ACCESS_VIOLATION;
    }

    //
    // Release security descriptor
    //
    ObReleaseObjectSecurity(deviceSecurityDescriptor, FALSE);

    return status;
}

/*++

Routine Description:
    Handles set security descriptor operations with comprehensive
    validation and error handling for fuzz testing.

Arguments:
    DeviceObject - Pointer to device object
    SecurityInformation - Security information to set
    SecurityDescriptor - Input buffer containing security descriptor
    Length - Length of input buffer
    IsUserMode - TRUE if called from user mode

Return Value:
    NTSTATUS code

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPSetSecurity(
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

    DbgPrint("MPSetSecurity: SecurityInfo=0x%08X, Buffer=%p, Length=%lu\n",
             SecurityInformation, SecurityDescriptor, Length);

    //
    // Validate security information flags
    //
    status = MPValidateSecurityInformation(SecurityInformation);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //
    // Validate input buffer
    //
    status = MPValidateSecurityBuffer(
        SecurityDescriptor,
        Length,
        FALSE,  // Read access
        IsUserMode
    );
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //
    // Handle NULL buffer or zero length
    //
    if (SecurityDescriptor == NULL || Length == 0)
    {
        DbgPrint("MPSetSecurity: NULL or zero-length buffer\n");
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate minimum size
    //
    if (Length < MIN_SECURITY_DESCRIPTOR_SIZE)
    {
        DbgPrint("MPSetSecurity: Buffer too small: %lu < %lu\n",
                 Length, MIN_SECURITY_DESCRIPTOR_SIZE);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Capture and validate security descriptor with SEH protection
    //
    __try
    {
        //
        // Allocate kernel buffer for security descriptor
        //
        capturedDescriptor = ExAllocatePoolWithTag(
            PagedPool,
            Length,
            'ceSM'  // 'MSec'
        );

        if (capturedDescriptor == NULL)
        {
            DbgPrint("MPSetSecurity: Failed to allocate memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        //
        // Copy security descriptor from user buffer
        //
        RtlCopyMemory(capturedDescriptor, SecurityDescriptor, Length);

        //
        // Validate security descriptor structure
        //
        isValid = RtlValidSecurityDescriptor(capturedDescriptor);
        
        if (!isValid)
        {
            DbgPrint("MPSetSecurity: Invalid security descriptor structure\n");
            status = STATUS_INVALID_SECURITY_DESCR;
            __leave;
        }

        //
        // Set security descriptor on device object
        //
        status = ObSetSecurityObjectByPointer(
            DeviceObject,
            SecurityInformation,
            capturedDescriptor
        );

        if (!NT_SUCCESS(status))
        {
            DbgPrint("MPSetSecurity: ObSetSecurityObjectByPointer failed 0x%08X\n",
                     status);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        DbgPrint("MPSetSecurity: Exception 0x%08X processing security descriptor\n",
                 status);
        status = STATUS_ACCESS_VIOLATION;
    }

    //
    // Free captured descriptor
    //
    if (capturedDescriptor != NULL)
    {
        ExFreePoolWithTag(capturedDescriptor, 'ceSM');
    }

    return status;
}

/*++

Routine Description:
    Dispatch routine for IRP_MJ_QUERY_SECURITY.
    Handles all fuzz test scenarios including invalid buffers,
    various lengths, and all security information types.

Arguments:
    DeviceObject - Pointer to device object
    Irp - Pointer to I/O request packet

Return Value:
    NTSTATUS code

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPDispatchQuerySecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    SECURITY_INFORMATION securityInformation;
    PSECURITY_DESCRIPTOR securityDescriptor;
    ULONG length;

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation(Irp);

    //
    // Extract parameters
    //
    securityInformation = irpSp->Parameters.QuerySecurity.SecurityInformation;
    length = irpSp->Parameters.QuerySecurity.Length;
    securityDescriptor = (PSECURITY_DESCRIPTOR)Irp->UserBuffer;

    DbgPrint("MPDispatchQuerySecurity: IRP=%p, SecurityInfo=0x%08X, Length=%lu\n",
             Irp, securityInformation, length);

    //
    // Call query security handler
    //
    status = MPQuerySecurity(
        DeviceObject,
        securityInformation,
        securityDescriptor,
        &length,
        Irp->RequestorMode == UserMode
    );

    //
    // Update IRP information
    //
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? length : 0;

    //
    // Complete the IRP
    //
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

/*++

Routine Description:
    Dispatch routine for IRP_MJ_SET_SECURITY.
    Handles all fuzz test scenarios including invalid buffers,
    various lengths, and all security information types.

Arguments:
    DeviceObject - Pointer to device object
    Irp - Pointer to I/O request packet

Return Value:
    NTSTATUS code

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MPDispatchSetSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    SECURITY_INFORMATION securityInformation;
    PSECURITY_DESCRIPTOR securityDescriptor;

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation(Irp);

    //
    // Extract parameters
    //
    securityInformation = irpSp->Parameters.SetSecurity.SecurityInformation;
    securityDescriptor = (PSECURITY_DESCRIPTOR)irpSp->Parameters.SetSecurity.SecurityDescriptor;

    DbgPrint("MPDispatchSetSecurity: IRP=%p, SecurityInfo=0x%08X\n",
             Irp, securityInformation);

    //
    // Call set security handler
    //
    status = MPSetSecurity(
        DeviceObject,
        securityInformation,
        securityDescriptor,
        sizeof(SECURITY_DESCRIPTOR),  // Minimum size
        Irp->RequestorMode == UserMode
    );

    //
    // Update IRP status
    //
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;

    //
    // Complete the IRP
    //
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}