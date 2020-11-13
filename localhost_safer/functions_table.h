#pragma once
#include <Windows.h>
#include <shellapi.h>


#include <wininet.h>

#include <tlhelp32.h>


// manually define because of WIN32_LEAN_AND_MEAN
#define NTSTATUS long 

typedef struct WSAData* LPWSADATA;
#define SOCKET UINT_PTR

// 
//
typedef enum _PROCESSINFOCLASS PROCESSINFOCLASS;

//
bool l_InternetCloseHandle(
    HINTERNET hInternet
);

HINTERNET l_HttpOpenRequestA(
    HINTERNET hConnect,
    LPCSTR    lpszVerb,
    LPCSTR    lpszObjectName,
    LPCSTR    lpszVersion,
    LPCSTR    lpszReferrer,
    LPCSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
);

HINTERNET l_InternetOpenA(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
);

bool l_HttpSendRequestA(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
);

//
HINTERNET l_InternetConnectA(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
);

int l_InternetReadFile(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
);


// ws2_32.dll
int l_closesocket(
    SOCKET s
);

int l_inet_pton(
    INT   Family,
    PCSTR pszAddrString,
    PVOID pAddrBuf
);

unsigned short l_htons
(
    unsigned short hostshort
);


SOCKET l_socket(
    int af,
    int type,
    int protocol
);

//
int l_setsockopt(
    SOCKET     s,
    int        level,
    int        optname,
    char* optval,
    int        optlen
);

int l_connect(
    SOCKET         s,
    struct sockaddr* name,
    int            namelen
);

int l_recv(
    SOCKET s,
    char* buf,
    int    len,
    int    flags
);

int l_send(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
);

int l_WSAStartup(
    WORD      wVersionRequired,
    LPWSADATA lpWSAData
);

int l_WSAGetLastError();

// ntdll.dll
NTSTATUS l_NtTerminateProcess(
    HANDLE               ProcessHandle,
    NTSTATUS             ExitStatus
);

NTSTATUS l_NtReadVirtualMemory(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    OUT PVOID               Buffer,
    IN ULONG                NumberOfBytesToRead,
    OUT PULONG              NumberOfBytesReaded
);

NTSTATUS l_NtWriteVirtualMemory(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritte
);

NTSTATUS l_NtGetContextThread(
    IN HANDLE               ThreadHandle,
    OUT PCONTEXT            pContex
);

NTSTATUS l_NtSetContextThread(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
);

NTSTATUS l_NtUnmapViewOfSection(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress
);

NTSTATUS l_NtResumeThread(
    IN HANDLE               ThreadHandle,
    OUT PULONG              SuspendCount
);


NTSTATUS l_NtClose(
    IN HANDLE Handle
);

NTSTATUS l_NtQueryInformationProcess(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID           ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG          ReturnLength
);


NTSTATUS l_RtlGetVersion(
    PRTL_OSVERSIONINFOW lpVersionInformation
);



// kernel32.dll
BOOL l_Process32NextW(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
);

BOOL l_Process32First(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
);

HANDLE l_CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
);

DWORD l_SizeofResource(
    HMODULE hModule,
    HRSRC   hResInfo
);

HRSRC l_FindResourceW(
    HMODULE hModule,
    LPWSTR  lpName,
    LPWSTR  lpType
);

HGLOBAL l_LoadResource(
    HMODULE hModule,
    HRSRC   hResInfo
);

LPVOID l_LockResource(
    HGLOBAL hResData
);

BOOL l_SetThreadContext(
    HANDLE        hThread,
    const CONTEXT* lpContext
);

BOOL l_GetThreadContext(
    HANDLE    hThread,
    LPCONTEXT lpContext
);

HANDLE l_CreateRemoteThread(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);

DWORD l_GetModuleBaseNameA(
    HANDLE  hProcess,
    HMODULE hModule,
    LPSTR   lpBaseName,
    DWORD   nSize
);


BOOL l_WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
);

BOOL l_ReadProcessMemory(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesRead
);

DWORD l_GetModuleFileNameExA(
    HANDLE  hProcess,
    HMODULE hModule,
    LPSTR   lpFilename,
    DWORD   nSize
);

BOOL l_EnumProcessModules(
    HANDLE  hProcess,
    HMODULE* lphModule,
    DWORD   cb,
    LPDWORD lpcbNeeded
);

BOOL l_GetProcessTimes(
    HANDLE     hProcess,
    LPFILETIME lpCreationTime,
    LPFILETIME lpExitTime,
    LPFILETIME lpKernelTime,
    LPFILETIME lpUserTime
);

BOOL l_GetExitCodeProcess(
    HANDLE  hProcess,
    LPDWORD lpExitCode
);

BOOL l_EnumProcesses(
    DWORD* lpidProcess,
    DWORD   cb,
    LPDWORD lpcbNeeded
);

HANDLE l_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

BOOL l_TerminateProcess(
    HANDLE hProcess,
    UINT   uExitCode
);

BOOL l_GetComputerNameA(
    LPSTR   lpBuffer,
    LPDWORD nSize
);

HANDLE l_GetCurrentThread(
);

void l_ExitProcess(
    UINT uExitCode
);

SIZE_T l_VirtualQuery(
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T                    dwLength
);

void l_GetSystemInfo(
    LPSYSTEM_INFO lpSystemInfo
);

BOOL l_VirtualFree(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
);

LPVOID l_VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

BOOL l_DuplicateHandle(
    HANDLE   hSourceProcessHandle,
    HANDLE   hSourceHandle,
    HANDLE   hTargetProcessHandle,
    LPHANDLE lpTargetHandle,
    DWORD    dwDesiredAccess,
    BOOL     bInheritHandle,
    DWORD    dwOptions
);

SIZE_T l_VirtualQueryEx(
    HANDLE                    hProcess,
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T                    dwLength
);

BOOL l_HeapWalk(
    HANDLE               hHeap,
    LPPROCESS_HEAP_ENTRY lpEntry
);

BOOL l_HeapFree(
    HANDLE                 hHeap,
    DWORD                  dwFlags,
    _Frees_ptr_opt_ LPVOID lpMem
);

LPVOID l_HeapAlloc(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
);

HANDLE l_GetProcessHeap();

DWORD l_ResumeThread(
    HANDLE hThread
);

BOOL l_VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);

DWORD l_GetProcessHeaps(
    DWORD   NumberOfHeaps,
    PHANDLE ProcessHeaps
);

DWORD l_SuspendThread(
    HANDLE hThread
);

BOOL l_GetExitCodeThread(
    HANDLE  hThread,
    LPDWORD lpExitCode
);

DWORD l_WaitForSingleObject(
    HANDLE hHandle,
    DWORD  dwMilliseconds
);

DWORD l_GetProcessId(
    HANDLE Process
);

HANDLE l_CreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);

BOOL l_VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);

BOOL l_WriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

BOOL l_CloseHandle(
    HANDLE hObject
);

BOOL l_UnmapViewOfFile(
    LPCVOID lpBaseAddress
);

HANDLE l_CreateFileMappingW(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCWSTR               lpName
);

LPVOID l_MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
);

HANDLE l_CreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

LPVOID l_VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);


BOOL l_ReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlappedh
);

DWORD l_GetFileSize(
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
);

BOOL l_FreeConsole();

DWORD l_GetCurrentProcessId();

BOOL l_CreateDirectoryA(
    LPCSTR                lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

BOOL l_IsDebuggerPresent();

BOOL l_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pDebuggerPresent);

BOOL l_GetVersionExA(LPOSVERSIONINFOA lpVersionInformation);

BOOL l_CreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

DWORD l_GetTempPathA(
    DWORD nBufferLength,
    LPSTR lpBuffer
);

DWORD l_GetTempFileNameA(
    LPCSTR lpPathName,
    LPCSTR lpPrefixString,
    UINT   uUnique,
    LPSTR  lpTempFileName
);

void l_Sleep(
    DWORD dwMilliseconds
);

HANDLE l_CreateMutexA(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL                  bInitialOwner,
    LPCSTR                lpName
);

DWORD l_GetLastError();

DWORD l_GetModuleFileNameA(
    HMODULE hModule,
    LPSTR   lpFilename,
    DWORD   nSize
);

DWORD l_GetModuleFileNameA(
    HMODULE hModule,
    LPSTR   lpFilename,
    DWORD   nSize
);

BOOL l_CopyFileA(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName,
    BOOL   bFailIfExists
);

BOOL l_SetFileAttributesA(
    LPCSTR lpFileName,
    DWORD  dwFileAttributes
);

LSTATUS l_RegCreateKeyExA(
    HKEY                        hKey,
    LPCSTR                      lpSubKey,
    DWORD                       Reserved,
    LPSTR                       lpClass,
    DWORD                       dwOptions,
    REGSAM                      samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY                       phkResult,
    LPDWORD                     lpdwDisposition
);

LSTATUS l_RegSetValueExA(
    HKEY       hKey,
    LPCSTR     lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
);

LSTATUS l_RegCloseKey(
    HKEY hKey
);

DWORD l_GetCurrentDirectoryA(
    DWORD  nBufferLength,
    LPTSTR lpBuffer
);

HANDLE l_CreateFileA(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

BOOL l_DeviceIoControl(
    HANDLE       hDevice,
    DWORD        dwIoControlCode,
    LPVOID       lpInBuffer,
    DWORD        nInBufferSize,
    LPVOID       lpOutBuffer,
    DWORD        nOutBufferSize,
    LPDWORD      lpBytesReturned,
    LPOVERLAPPED lpOverlapped
);

BOOL l_IsWow64Process(
    HANDLE hProcess,
    PBOOL  Wow64Process
);

HANDLE l_GetCurrentProcess();

BOOL l_DeleteFileA(
    LPCSTR lpFileName
);

// ole32.dll
HRESULT l_CoInitializeEx(
    LPVOID pvReserved,
    DWORD  dwCoInit
);

void l_CoUninitialize();

// shell32.dll
BOOL l_ShellExecuteExA(
    SHELLEXECUTEINFOA* pExecInfo
);

// shlwapi.dll

BOOL l_PathFileExistsA(
    LPCSTR pszPath
);


// advapi32.dll
LSTATUS l_RegOpenKeyExA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    DWORD  ulOptions,
    REGSAM samDesired,
    PHKEY  phkResult
);

LSTATUS l_RegGetValueA(
    HKEY    hkey,
    LPCSTR  lpSubKey,
    LPCSTR  lpValue,
    DWORD   dwFlags,
    LPDWORD pdwType,
    PVOID   pvData,
    LPDWORD pcbData
);

BOOL l_GetUserNameA(
    LPSTR   lpBuffer,
    LPDWORD pcbBuffer

);

//
BOOL l_OpenProcessToken(
    HANDLE  ProcessHandle,
    DWORD   DesiredAccess,
    PHANDLE TokenHandle

);

BOOL l_LookupPrivilegeValueA(
    LPCSTR lpSystemName,
    LPCSTR lpName,
    PLUID  lpLuid

);

BOOL l_AdjustTokenPrivileges(
    HANDLE            TokenHandle,
    BOOL              DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD             BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD            ReturnLength

);