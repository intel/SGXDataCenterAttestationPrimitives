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

#include "Power.h"
#include "Power.tmh"
#include "Utility.h"
#include "sgx_lc_msr_public.h"
#include "Key.h"

//static BOOLEAN OwnFLC = FALSE;
sgx_get_launch_support_output_t launch_support_info = { 0 };

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FLCMSREvtDeviceD0Exit)
#endif // ALLOC_PRAGMA

static BOOLEAN is_PLE_OPT_IN()
{
    ULONG ulPLEOptIn = 0;

    //Get PLE Opt-In from the Registry
    WDFKEY key;
    NTSTATUS status = WdfDriverOpenParametersRegistryKey(WdfGetDriver(), KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &key);
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_POWER, "%!FUNC! WdfDriverOpenParametersRegistryKey failed %!STATUS!", status);
    }
    else
    {

        DECLARE_CONST_UNICODE_STRING(valueName, SGX_PLE_REGISTRY_OPT_IN_REGISTRY);
        status = WdfRegistryQueryULong(key, &valueName, &ulPLEOptIn);
        if (!NT_SUCCESS(status))
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_POWER, "%!FUNC! WdfRegistryQueryULong failed %!STATUS!", status);
        }
        WdfRegistryClose(key);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "PLE_OPT_IN:0x%x", ulPLEOptIn);

    if (ulPLEOptIn == 1)
        return TRUE;
    else
        return FALSE;
}

NTSTATUS
FLCMSREvtDeviceD0Entry(
    IN WDFDEVICE                Device,
    IN WDF_POWER_DEVICE_STATE   RecentPowerState
)
{
    ULONG_PTR ret = 0;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(RecentPowerState);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "%!FUNC! Entry");

    if (is_OS_support_FLC())
        launch_support_info.configurationFlags = SGX_LCP_OS_PERMISSION;
    else
        return STATUS_SUCCESS;

    //clear the platform support bit, set the bit if and only if successfuly update MSR
    launch_support_info.configurationFlags &= ~SGX_LCP_PLATFORM_SUPPORT;

    if (is_PLE_OPT_IN())
    {
        launch_support_info.configurationFlags |= SGX_PLE_REGISTRY_OPT_IN;

        if (is_HW_support_FLC())
        {
            ret = KeIpiGenericCall(IpiGenericCall, 0);
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "Write MSRs finished %llu", ret);

            if (ret == 0)
            {
                launch_support_info.configurationFlags |= SGX_LCP_PLATFORM_SUPPORT;
                launch_support_info.pubKeyHash.pubKeyHash_Value_0 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_0;
                launch_support_info.pubKeyHash.pubKeyHash_Value_1 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_1;
                launch_support_info.pubKeyHash.pubKeyHash_Value_2 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_2;
                launch_support_info.pubKeyHash.pubKeyHash_Value_3 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_3;
            }
        }
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "%!FUNC! Exit %x", launch_support_info.configurationFlags);

    //always return success because we need to support IOCTL_SGX_GETLAUNCHSUPPORT
    return STATUS_SUCCESS;
}

NTSTATUS
FLCMSREvtDeviceD0Exit(
    IN WDFDEVICE                Device,
    IN WDF_POWER_DEVICE_STATE   PowerState
)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(PowerState);

    return STATUS_SUCCESS;
}

NTSTATUS
FLCMSREvtDevicePrepareHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFCMRESLIST ResourceList,
    _In_ WDFCMRESLIST ResourceListTranslated
)
/*++

Routine Description:

In this callback, the driver does whatever is necessary to make the
hardware ready to use.  In the case of a USB device, this involves
reading and selecting descriptors.

Arguments:

Device - handle to a device

Return Value:

NT status value

--*/
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(ResourceList);
    UNREFERENCED_PARAMETER(ResourceListTranslated);

    return STATUS_SUCCESS;
}