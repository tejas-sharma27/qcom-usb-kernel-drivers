/*++

Copyright (c) Qualcomm Inc. All rights reserved.

Module Name:
    MPSecurityIntegration.c

Abstract:
    Integration code for security handlers in NDIS miniport driver.
    This file shows how to integrate MPSecurity.c handlers into your driver.

--*/

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "MPMain.h"
#include "MPSecurity.h"

/*++

Routine Description:
    Example of how to register security dispatch handlers in DriverEntry.
    Add this code to your DriverEntry routine.

Arguments:
    DriverObject - Pointer to driver object
    RegistryPath - Registry path for driver

Return Value:
    NTSTATUS code

--*/
NTSTATUS
MPRegisterSecurityHandlers(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    //
    // Register IRP_MJ_QUERY_SECURITY handler
    //
    DriverObject->MajorFunction[IRP_MJ_QUERY_SECURITY] = MPDispatchQuerySecurity;

    //
    // Register IRP_MJ_SET_SECURITY handler
    //
    DriverObject->MajorFunction[IRP_MJ_SET_SECURITY] = MPDispatchSetSecurity;

    DbgPrint("MPRegisterSecurityHandlers: Security handlers registered\n");

    return STATUS_SUCCESS;
}

/*++

Routine Description:
    Example of enhanced device creation with security descriptor.
    Use this when creating device objects to ensure proper security setup.

Arguments:
    DriverObject - Pointer to driver object
    DeviceExtensionSize - Size of device extension
    DeviceName - Device name
    DeviceType - Device type
    DeviceCharacteristics - Device characteristics
    Exclusive - Exclusive flag
    DeviceObject - Pointer to receive device object

Return Value:
    NTSTATUS code

--*/
NTSTATUS
MPCreateSecureDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONG DeviceExtensionSize,
    _In_opt_ PUNICODE_STRING DeviceName,
    _In_ DEVICE_TYPE DeviceType,
    _In_ ULONG DeviceCharacteristics,
    _In_ BOOLEAN Exclusive,
    _Out_ PDEVICE_OBJECT *DeviceObject
)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING sddlString;

    //
    // Define SDDL string for device security
    // This allows:
    // - SYSTEM: Full control
    // - Administrators: Full control
    // - Users: Read/Write access
    //
    RtlInitUnicodeString(&sddlString,
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;WD)");

    //
    // Create device with security descriptor
    //
    status = IoCreateDeviceSecure(
        DriverObject,
        DeviceExtensionSize,
        DeviceName,
        DeviceType,
        DeviceCharacteristics,
        Exclusive,
        &sddlString,
        NULL,  // Device class GUID
        &deviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("MPCreateSecureDevice: IoCreateDeviceSecure failed 0x%08X\n",
                 status);
        return status;
    }

    *DeviceObject = deviceObject;

    DbgPrint("MPCreateSecureDevice: Secure device created successfully\n");

    return STATUS_SUCCESS;
}

/*++

Routine Description:
    Example of how to handle security in IOCTL dispatch routine.
    Add security checks to your existing IOCTL handler.

Arguments:
    DeviceObject - Pointer to device object
    Irp - Pointer to I/O request packet

Return Value:
    NTSTATUS code

--*/
NTSTATUS
MPDispatchDeviceControlWithSecurity(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    ULONG ioControlCode;
    PVOID inputBuffer;
    PVOID outputBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    //
    // Get buffers based on transfer type
    //
    switch (METHOD_FROM_CTL_CODE(ioControlCode))
    {
        case METHOD_BUFFERED:
            inputBuffer = Irp->AssociatedIrp.SystemBuffer;
            outputBuffer = Irp->AssociatedIrp.SystemBuffer;
            break;

        case METHOD_IN_DIRECT:
        case METHOD_OUT_DIRECT:
            inputBuffer = Irp->AssociatedIrp.SystemBuffer;
            outputBuffer = (Irp->MdlAddress != NULL) ?
                MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority) :
                NULL;
            break;

        case METHOD_NEITHER:
            inputBuffer = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
            outputBuffer = Irp->UserBuffer;
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            goto Complete;
    }

    //
    // Validate buffers with security checks
    //
    if (inputBufferLength > 0)
    {
        status = MPValidateSecurityBuffer(
            inputBuffer,
            inputBufferLength,
            FALSE,  // Read access
            Irp->RequestorMode == UserMode
        );

        if (!NT_SUCCESS(status))
        {
            DbgPrint("MPDispatchDeviceControlWithSecurity: Input buffer validation failed 0x%08X\n",
                     status);
            goto Complete;
        }
    }

    if (outputBufferLength > 0)
    {
        status = MPValidateSecurityBuffer(
            outputBuffer,
            outputBufferLength,
            TRUE,  // Write access
            Irp->RequestorMode == UserMode
        );

        if (!NT_SUCCESS(status))
        {
            DbgPrint("MPDispatchDeviceControlWithSecurity: Output buffer validation failed 0x%08X\n",
                     status);
            goto Complete;
        }
    }

    //
    // Process IOCTL (add your existing IOCTL handling here)
    //
    status = STATUS_SUCCESS;

Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}