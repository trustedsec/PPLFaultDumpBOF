
#include <phnt_windows.h>
#include <phnt.h>

// Finds the address within buf of the image entrypoint 
PVOID FindEntrypointVA(void * buf);

// Build a payload that consists of the given benign DLL with its entrypoint overwritten by our shellcode
BOOL WriteShellcode(PVOID pBuf, PVOID shellcode, DWORD shellcodelen, DWORD* bytesWritten);
