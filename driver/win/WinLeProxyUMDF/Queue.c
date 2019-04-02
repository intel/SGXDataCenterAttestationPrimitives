/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*++

Module Name:

    queue.c

Abstract:

    This file contains the queue entry points and callbacks.

Environment:

    User-mode Driver Framework 2

--*/

#include "driver.h"
#include "queue.tmh"

#include "FLC_LE.h"
#include "sgx_launch_public.h"
#include "openssl/sha.h"


NTSTATUS
WinLeProxyUMDFQueueInitialize(
    _In_ WDFDEVICE Device
)
/*++

Routine Description:

     The I/O dispatch callbacks for the frameworks device object
     are configured in this function.

     A single default I/O Queue is configured for parallel request
     processing, and a driver context memory allocation is created
     to hold our structure QUEUE_CONTEXT.

Arguments:

    Device - Handle to a framework device object.

Return Value:

    VOID

--*/
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    //
    // Configure a default queue so that requests that are not
    // configure-fowarded using WdfDeviceConfigureRequestDispatching to goto
    // other queues get dispatched here.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchSequential
    );

    queueConfig.EvtIoDeviceControl = WinLeProxyUMDFEvtIoDeviceControl;
    queueConfig.EvtIoStop = WinLeProxyUMDFEvtIoStop;

    status = WdfIoQueueCreate(
                 Device,
                 &queueConfig,
                 WDF_NO_OBJECT_ATTRIBUTES,
                 &queue
             );

    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return status;
}

VOID
WinLeProxyUMDFEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
/*++

Routine Description:

    This event is invoked when the framework receives IRP_MJ_DEVICE_CONTROL request.

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    OutputBufferLength - Size of the output buffer in bytes

    InputBufferLength - Size of the input buffer in bytes

    IoControlCode - I/O control code.

Return Value:

    VOID

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    size_t buffer_size = 0;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                TRACE_QUEUE,
                "%!FUNC! Queue 0x%p, Request 0x%p OutputBufferLength %d InputBufferLength %d IoControlCode %d",
                Queue, Request, (int)OutputBufferLength, (int)InputBufferLength, IoControlCode);

    if (IoControlCode == IOCTL_SGX_GETTOKEN)
    {
        sgx_launch_request_t req = { 0 };
        WDFMEMORY memory = NULL;


        //if the PLE is not loaded, try to load it.
        if (entry == NULL)
            entry = start_launch_enclave();

        if (entry == NULL)
        {
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Failed to load PLE");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        status = WdfRequestRetrieveInputMemory(Request, &memory);
        if (status != STATUS_SUCCESS)
        {
            goto end;
        }

        sgx_launch_token_request_t* buffer_in = (sgx_launch_token_request_t*)WdfMemoryGetBuffer(memory, &buffer_size);
        if (buffer_in == NULL || buffer_size < sizeof(sgx_launch_token_request_t) || buffer_in->version != 0)
        {
            buffer_size = 0;
            goto end;
        }

        status = WdfRequestRetrieveOutputMemory(Request, &memory);
        if (status != STATUS_SUCCESS)
        {
            buffer_size = 0;
            goto end;
        }

        sgx_le_output_t* buffer_out = (sgx_le_output_t*)WdfMemoryGetBuffer(memory, &buffer_size);
        if (buffer_out == NULL || buffer_size < sizeof(sgx_le_output_t))
        {
            buffer_size = 0;
            goto end;
        }

        /*caculate the MRSigner*/
        SHA256_CTX sha256;
        sgx_sha256_hash_t value;

        SHA256_Init(&sha256);
        SHA256_Update(&sha256, buffer_in->css.key.modulus, SE_KEY_SIZE);
        SHA256_Final(value, &sha256);

        req.attributes = buffer_in->secs_attr.flags;
        req.xfrm = buffer_in->secs_attr.xfrm;
        memcpy_s(req.mrenclave, 32, &buffer_in->css.body.enclave_hash, sizeof(sgx_measurement_t));
        memcpy_s(req.mrsigner, 32, &value, sizeof(sgx_sha256_hash_t));

        try
        {
            sgx_get_token(&req, entry);
        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_QUEUE,
                        "sgx_get_token crashed");
            goto end;
        }

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "sgx_get_token finished");

        errno_t err = memcpy_s(buffer_out, buffer_size, &req.output, sizeof(sgx_le_output_t));
        if (err)
            goto end;

        status = STATUS_SUCCESS;
    }
    else
    {
        WDFDEVICE  device = NULL;
        WDFIOTARGET ioTargetHandle = NULL;
        WDF_REQUEST_SEND_OPTIONS options;

        device = WdfIoQueueGetDevice(Queue);
        ioTargetHandle = WdfDeviceGetIoTarget(device);

        WdfRequestFormatRequestUsingCurrentType(Request);

        WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                      WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
        WdfRequestSend(Request, ioTargetHandle, &options);

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "%!FUNC! forward the request to the KMDF driver");
        return;
    }

end:
    WdfRequestCompleteWithInformation(Request, status, buffer_size);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "%!FUNC! Exit");
    return;
}

VOID
WinLeProxyUMDFEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
/*++

Routine Description:

    This event is invoked for a power-managed queue before the device leaves the working state (D0).

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    ActionFlags - A bitwise OR of one or more WDF_REQUEST_STOP_ACTION_FLAGS-typed flags
                  that identify the reason that the callback function is being called
                  and whether the request is cancelable.

Return Value:

    VOID

--*/
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                TRACE_QUEUE,
                "%!FUNC! Queue 0x%p, Request 0x%p ActionFlags %d",
                Queue, Request, ActionFlags);

    return;
}

