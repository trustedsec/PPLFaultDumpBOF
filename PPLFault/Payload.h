#pragma once

#include <phnt_windows.h>


BOOL BuildPayload(
    HANDLE hBenignDll,
    char** payloadBuffer,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath,
    DWORD* len,
    uint8_t* shellcode,
    DWORD shellcodelen);
