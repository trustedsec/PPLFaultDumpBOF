#pragma once
#include <Windows.h>
#include <cfapi.h>
#define WINBOOL int
#define GetFNPtr(hmod, fname, varname, type) type varname = (type)GetProcAddress(hmod,fname)

typedef BOOLEAN(WINAPI* fpTryAcquireSRWLockExclusive)(PSRWLOCK SRWLock);
typedef VOID(WINAPI* fpReleaseSRWLockExclusive)(PSRWLOCK SRWLock);
typedef WINBOOL(WINAPI* fpSetFilePointerEx)(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod);
typedef HRESULT(__stdcall
    * fpCfExecute)(
        CONST CF_OPERATION_INFO* OpInfo,
        CF_OPERATION_PARAMETERS* OpParams
        );
typedef
NTSTATUS
(*fpRtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled
);

typedef   
HRESULT (__stdcall
*fpNtSetSystemInformation)(
    int SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
);

typedef PIMAGE_NT_HEADERS (__stdcall *fpImageNtHeader)(PVOID Base);
typedef PVOID  (__stdcall *fpImageRvaToVa)(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva, PIMAGE_SECTION_HEADER* LastRvaSection);
typedef BOOLEAN (APIENTRY *fpCreateSymbolicLinkW)(LPCWSTR lpSymlinkFileName, LPCWSTR lpTargetFileName, DWORD dwFlags);
typedef WINBOOL (WINAPI *fpCreateDirectoryW)(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
typedef WINBOOL (WINAPI *fpSetFileInformationByHandle)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);

typedef ULONGLONG (WINAPI *fpGetTickCount64)(VOID);
typedef WINBOOL (WINAPI *fpWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);


typedef HRESULT (__stdcall
*fpCfRegisterSyncRoot)(
    LPCWSTR SyncRootPath,
    CONST CF_SYNC_REGISTRATION* Registration,
    CONST CF_SYNC_POLICIES* Policies,
    CF_REGISTER_FLAGS RegisterFlags
);

typedef
HRESULT (__stdcall
*fpCfConnectSyncRoot)(
    LPCWSTR SyncRootPath,
    CONST CF_CALLBACK_REGISTRATION* CallbackTable,
    LPCVOID CallbackContext,
    CF_CONNECT_FLAGS ConnectFlags,
    CF_CONNECTION_KEY* ConnectionKey
);

typedef
HRESULT (__stdcall
*fpCfUnregisterSyncRoot)(
    LPCWSTR SyncRootPath
);
typedef WINBOOL (WINAPI *fpGetFileAttributesExW)(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
typedef HRESULT (WINAPI *fpCfDisconnectSyncRoot)(
    CF_CONNECTION_KEY ConnectionKey
);