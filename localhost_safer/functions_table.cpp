#include "functions_table_utils.h"
#include <Windows.h>

#include "functions_table.h"
#include <wininet.h>



//
bool l_InternetCloseHandle(
    HINTERNET hInternet
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_wininet_dll(6);
    typedef HINTERNET(__stdcall* FUNCTION_POINTER_CAST)(
        HINTERNET
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hInternet
        );
    }
    else {
        return false;
    }


}

//
HINTERNET l_HttpOpenRequestA(
    HINTERNET hConnect,
    LPCSTR    lpszVerb,
    LPCSTR    lpszObjectName,
    LPCSTR    lpszVersion,
    LPCSTR    lpszReferrer,
    LPCSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_wininet_dll(5);
    typedef HINTERNET(__stdcall* FUNCTION_POINTER_CAST)(
        HINTERNET,
        LPCSTR,
        LPCSTR,
        LPCSTR,
        LPCSTR,
        LPCSTR*,
        DWORD,
        DWORD_PTR
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hConnect,
            lpszVerb,
            lpszObjectName,
            lpszVersion,
            lpszReferrer,
            lplpszAcceptTypes,
            dwFlags,
            dwContext
        );
    }
    else {
        return NULL;
    }


}

//
HINTERNET l_InternetOpenA(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_wininet_dll(4);
    typedef HINTERNET(__stdcall* FUNCTION_POINTER_CAST)(
        LPCSTR,
        DWORD,
        LPCSTR,
        LPCSTR,
        DWORD
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpszAgent,
            dwAccessType,
            lpszProxy,
            lpszProxyBypass,
            dwFlags
        );
    }
    else {
        return NULL;
    }


}

//
bool l_HttpSendRequestA(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_wininet_dll(3);
    typedef bool(__stdcall* FUNCTION_POINTER_CAST)(
        HINTERNET,
        LPCSTR,
        DWORD,
        LPVOID,
        DWORD
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hRequest,
            lpszHeaders,
            dwHeadersLength,
            lpOptional,
            dwOptionalLength
        );
    }
    else {
        return false;
    }

}

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
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_wininet_dll(2);
    typedef HINTERNET(__stdcall* FUNCTION_POINTER_CAST)(
        HINTERNET,
        LPCSTR,
        INTERNET_PORT,
        LPCSTR,
        LPCSTR,
        DWORD,
        DWORD,
        DWORD_PTR
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hInternet,
            lpszServerName,
            nServerPort,
            lpszUserName,
            lpszPassword,
            dwService,
            dwFlags,
            dwContext
        );
    }
    else {
        return NULL;
    }

}



//
int l_InternetReadFile(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_wininet_dll(1);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)(
        HINTERNET,
        LPVOID,
        DWORD,
        LPDWORD
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hFile,
            lpBuffer,
            dwNumberOfBytesToRead,
            lpdwNumberOfBytesRead
        );
    }
    else {
        return 0;
    }

}


//
int l_closesocket(
    SOCKET s
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(10);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)(
        SOCKET 
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
             s
        );
    }
    else {
        return 0;
    }

}

//
int l_inet_pton(
    INT   Family,
    PCSTR pszAddrString,
    PVOID pAddrBuf
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(9);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)(
        INT,
        PCSTR,
        PVOID
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            Family,
            pszAddrString,
            pAddrBuf
        );
    }
    else {
        return 0;
    }

}

//
unsigned short l_htons(
    unsigned short hostshort
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(8);
    typedef u_short(__stdcall* FUNCTION_POINTER_CAST)(
        unsigned short
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hostshort
        );
    }
    else {
        return 0;
    }

}

//
SOCKET l_socket(
    int af,
    int type,
    int protocol
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(7);
    typedef SOCKET(__stdcall* FUNCTION_POINTER_CAST)(
        int,
        int,
        int
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            af,
            type,
            protocol
        );
    }
    else {
        return INVALID_SOCKET;
    }

}



//
int l_setsockopt(
    SOCKET     s,
    int        level,
    int        optname,
    char* optval,
    int        optlen
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(6);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)(
        SOCKET,
        int,
        int,
        char*,
        int
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            s,
            level,
            optname,
            optval,
            optlen
        );
    }
    else {
        return 0;
    }

}

//
int l_connect(
    SOCKET         s,
    sockaddr* name,
    int            namelen
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(5);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)(
        SOCKET,
        const sockaddr*,
        int
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            s,
            name,
            namelen
        );
    }
    else {
        return 0;
    }

}

int l_recv(
    SOCKET s,
    char* buf,
    int    len,
    int    flags
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(4);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)(
        SOCKET,
        char*,
        int,
        int
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            s,
            buf,
            len,
            flags
        );
    }
    else {
        return 0;
    }

}

int l_send(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(3);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)(
        SOCKET,
        const char*,
        int,
        int
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            s,
            buf,
            len,
            flags
        );
    }
    else {
        return 0;
    }

}

int l_WSAStartup(
    WORD      wVersionRequired,
    LPWSADATA lpWSAData
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(2);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)(
        WORD,
        LPWSADATA
        );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            wVersionRequired,
            lpWSAData
        );
    }
    else {
        return 0;
    }

}


int l_WSAGetLastError()
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ws2_32_dll(1);
    typedef int(__stdcall* FUNCTION_POINTER_CAST)();

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast();
    }
    else {
        return 0;
    }

}

// kernel32.dll
BOOL l_IsDebuggerPresent()
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(1);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)();

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast();
    }
    else {
        return true;
    }

}

BOOL l_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pDebuggerPresent)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(2);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)(HANDLE, PBOOL);

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(hProcess, pDebuggerPresent);
    }
    else {
        return true;
    }

}

BOOL l_GetVersionExA(LPOSVERSIONINFOA lpVersionInformation)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(3);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)(LPOSVERSIONINFOA);

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(lpVersionInformation);
    }
    else {
        return true;
    }

}

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
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(4);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR,
            LPSTR,
            LPSECURITY_ATTRIBUTES,
            LPSECURITY_ATTRIBUTES,
            BOOL,
            DWORD,
            LPVOID,
            LPCSTR,
            LPSTARTUPINFOA,
            LPPROCESS_INFORMATION
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }
    else {
        return true;
    }

}


DWORD l_GetTempPathA(
    DWORD nBufferLength,
    LPSTR lpBuffer
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(5);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            DWORD,
            LPSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            nBufferLength,
            lpBuffer
        );
    }
    else {
        return 0;
    }

}


DWORD l_GetTempFileNameA(
    LPCSTR lpPathName,
    LPCSTR lpPrefixString,
    UINT   uUnique,
    LPSTR  lpTempFileName
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(6);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR,
            LPCSTR,
            UINT,
            LPSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpPathName,
            lpPrefixString,
            uUnique,
            lpTempFileName
        );
    }
    else {
        return 0;
    }

}


void l_Sleep(
    DWORD dwMilliseconds
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(7);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        function_pointer_cast(
            dwMilliseconds
        );
    }
    else {
        return;
    }

}


HANDLE l_CreateMutexA(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL                  bInitialOwner,
    LPCSTR                lpName
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(8);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPSECURITY_ATTRIBUTES,
            BOOL,
            LPCSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpMutexAttributes,
            bInitialOwner,
            lpName
        );
    }
    else {
        return NULL;
    }

}



DWORD l_GetLastError(
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(9);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
        );
    }
    else {
        return 0;
    }

}


DWORD l_GetModuleFileNameA(
    HMODULE hModule,
    LPSTR   lpFilename,
    DWORD   nSize
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(10);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HMODULE,
            LPSTR,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hModule,
            lpFilename,
            nSize
        );
    }
    else {
        return 0;
    }

}


BOOL l_CreateDirectoryA(
    LPCSTR                lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(11);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR,
            LPSECURITY_ATTRIBUTES
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpPathName,
            lpSecurityAttributes
        );
    }
    else {
        return FALSE;
    }
}


BOOL l_CopyFileA(
    LPCSTR lpExistingFileName,
    LPCSTR lpNewFileName,
    BOOL   bFailIfExists
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(12);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR,
            LPCSTR,
            BOOL
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpExistingFileName,
            lpNewFileName,
            bFailIfExists
        );
    }
    else {
        return FALSE;
    }
}

BOOL l_SetFileAttributesA(
    LPCSTR lpFileName,
    DWORD  dwFileAttributes
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(13);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpFileName,
            dwFileAttributes
        );
    }
    else {
        return FALSE;
    }
}


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
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(14);
    typedef LSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            HKEY,
            LPCSTR,
            DWORD,
            LPSTR,
            DWORD,
            REGSAM,
            const LPSECURITY_ATTRIBUTES,
            PHKEY,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hKey,
            lpSubKey,
            Reserved,
            lpClass,
            dwOptions,
            samDesired,
            lpSecurityAttributes,
            phkResult,
            lpdwDisposition
        );
    }
    else {
        return 0;
    }
}


LSTATUS l_RegSetValueExA(
    HKEY       hKey,
    LPCSTR     lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(15);
    typedef LSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            HKEY,
            LPCSTR,
            DWORD,
            DWORD,
            const BYTE*,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hKey,
            lpValueName,
            Reserved,
            dwType,
            lpData,
            cbData
        );
    }
    else {
        return 0;
    }

}


LSTATUS l_RegCloseKey(
    HKEY hKey
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(16);
    typedef LSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            HKEY
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hKey
        );
    }
    else {
        return 0;
    }
}

DWORD l_GetCurrentDirectoryA(
    DWORD  nBufferLength,
    LPTSTR lpBuffer
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(17);
    typedef LSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            DWORD,
            LPTSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            nBufferLength,
            lpBuffer
        );
    }
    else {
        return 0;
    }

}

HANDLE l_CreateFileA(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(18);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR,
            DWORD,
            DWORD,
            LPSECURITY_ATTRIBUTES,
            DWORD,
            DWORD,
            HANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile
        );
    }
    else {
        return NULL;
    }

}


BOOL l_DeviceIoControl(
    HANDLE       hDevice,
    DWORD        dwIoControlCode,
    LPVOID       lpInBuffer,
    DWORD        nInBufferSize,
    LPVOID       lpOutBuffer,
    DWORD        nOutBufferSize,
    LPDWORD      lpBytesReturned,
    LPOVERLAPPED lpOverlapped
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(19);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            DWORD,
            LPVOID,
            DWORD,
            LPVOID,
            DWORD,
            LPDWORD,
            LPOVERLAPPED
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hDevice,
            dwIoControlCode,
            lpInBuffer,
            nInBufferSize,
            lpOutBuffer,
            nOutBufferSize,
            lpBytesReturned,
            lpOverlapped
        );
    }
    else {
        return FALSE;
    }

}


BOOL l_IsWow64Process(
    HANDLE hProcess,
    PBOOL  Wow64Process
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(20);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            PBOOL
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            Wow64Process
        );
    }
    else {
        return FALSE;
    }

}

HANDLE l_GetCurrentProcess(
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(21);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
        );
    }
    else {
        return NULL;
    }

}


BOOL l_DeleteFileA(
    LPCSTR lpFileName
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(22);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpFileName
        );
    }
    else {
        return NULL;
    }

}

DWORD l_GetCurrentProcessId(
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(23);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(

        );
    }
    else {
        return 0;
    }

}

BOOL l_FreeConsole(
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(24);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(

        );
    }
    else {
        return FALSE;
    }

}

DWORD l_GetFileSize(
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(25);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hFile,
            lpFileSizeHigh
        );
    }
    else {
        return 0;
    }

}

BOOL l_ReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlappedh
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(26);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPVOID,
            DWORD,
            LPDWORD,
            LPOVERLAPPED
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hFile,
            lpBuffer,
            nNumberOfBytesToRead,
            lpNumberOfBytesRead,
            lpOverlappedh
        );
    }
    else {
        return FALSE;
    }

}

LPVOID l_VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(27);
    typedef LPVOID(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPVOID,
            SIZE_T,
            DWORD,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lpAddress,
            dwSize,
            flAllocationType,
            flProtect
        );
    }
    else {
        return FALSE;
    }

}


HANDLE l_CreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(28);
    typedef LPVOID(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCWSTR,
            DWORD,
            DWORD,
            LPSECURITY_ATTRIBUTES,
            DWORD,
            DWORD,
            HANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile
        );
    }
    else {
        return NULL;
    }

}


LPVOID l_MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(29);
    typedef LPVOID(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            DWORD,
            DWORD,
            DWORD,
            SIZE_T
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hFileMappingObject,
            dwDesiredAccess,
            dwFileOffsetHigh,
            dwFileOffsetLow,
            dwNumberOfBytesToMap
        );
    }
    else {
        return NULL;
    }

}

HANDLE l_CreateFileMappingW(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCWSTR               lpName
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(30);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPSECURITY_ATTRIBUTES,
            DWORD,
            DWORD,
            DWORD,
            LPCWSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hFile,
            lpFileMappingAttributes,
            flProtect,
            dwMaximumSizeHigh,
            dwMaximumSizeLow,
            lpName
        );
    }
    else {
        return NULL;
    }

}

BOOL l_UnmapViewOfFile(
    LPCVOID lpBaseAddress
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(31);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCVOID
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpBaseAddress
        );
    }
    else {
        return FALSE;
    }

}

BOOL l_CloseHandle(
    HANDLE hObject
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(32);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hObject
        );
    }
    else {
        return FALSE;
    }

}

BOOL l_WriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(33);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPCVOID,
            DWORD,
            LPDWORD,
            LPOVERLAPPED
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hFile,
            lpBuffer,
            nNumberOfBytesToWrite,
            lpNumberOfBytesWritten,
            lpOverlapped
        );
    }
    else {
        return FALSE;
    }

}

BOOL l_VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(34);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPVOID,
            SIZE_T,
            DWORD,
            PDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lpAddress,
            dwSize,
            flNewProtect,
            lpflOldProtect
        );
    }
    else {
        return FALSE;
    }

}

HANDLE l_CreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(35);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPSECURITY_ATTRIBUTES,
            SIZE_T,
            LPTHREAD_START_ROUTINE,
            __drv_aliasesMem LPVOID,
            DWORD,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpThreadAttributes,
            dwStackSize,
            lpStartAddress,
            lpParameter,
            dwCreationFlags,
            lpThreadId
        );
    }
    else {
        return NULL;
    }

}

DWORD l_GetProcessId(
    HANDLE Process
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(36);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            Process
        );
    }
    else {
        return 0;
    }

}

DWORD l_WaitForSingleObject(
    HANDLE hHandle,
    DWORD  dwMilliseconds
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(37);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hHandle,
            dwMilliseconds
        );
    }
    else {
        return 0;
    }

}

BOOL l_GetExitCodeThread(
    HANDLE  hThread,
    LPDWORD lpExitCode
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(38);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hThread,
            lpExitCode
        );
    }
    else {
        return FALSE;
    }

}

DWORD l_SuspendThread(
    HANDLE hThread
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(39);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hThread
        );
    }
    else {
        return 0;
    }

}

DWORD l_GetProcessHeaps(
    DWORD   NumberOfHeaps,
    PHANDLE ProcessHeaps
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(40);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            DWORD,
            PHANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            NumberOfHeaps,
            ProcessHeaps
        );
    }
    else {
        return 0;
    }

}

BOOL l_VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(41);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPVOID,
            SIZE_T,
            DWORD,
            PDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpAddress,
            dwSize,
            flNewProtect,
            lpflOldProtect
        );
    }
    else {
        return FALSE;
    }

}


DWORD l_ResumeThread(
    HANDLE hThread
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(42);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hThread
        );
    }
    else {
        return 0;
    }

}


HANDLE l_GetProcessHeap(
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(43);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
        );
    }
    else {
        return NULL;
    }

}

LPVOID l_HeapAlloc(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(44);
    typedef LPVOID(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            DWORD,
            SIZE_T
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hHeap,
            dwFlags,
            dwBytes
        );
    }
    else {
        return NULL;
    }

}

BOOL l_HeapFree(
    HANDLE                 hHeap,
    DWORD                  dwFlags,
    _Frees_ptr_opt_ LPVOID lpMem
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(45);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            DWORD,
            _Frees_ptr_opt_ LPVOID
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hHeap,
            dwFlags,
            lpMem
        );
    }
    else {
        return FALSE;
    }

}

BOOL l_HeapWalk(
    HANDLE               hHeap,
    LPPROCESS_HEAP_ENTRY lpEntry
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(46);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPPROCESS_HEAP_ENTRY
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hHeap,
            lpEntry
        );
    }
    else {
        return FALSE;
    }

}


SIZE_T l_VirtualQueryEx(
    HANDLE                    hProcess,
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T                    dwLength
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(47);
    typedef SIZE_T(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPCVOID,
            PMEMORY_BASIC_INFORMATION,
            SIZE_T
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lpAddress,
            lpBuffer,
            dwLength
        );
    }
    else {
        return NULL;
    }

}


BOOL l_DuplicateHandle(
    HANDLE   hSourceProcessHandle,
    HANDLE   hSourceHandle,
    HANDLE   hTargetProcessHandle,
    LPHANDLE lpTargetHandle,
    DWORD    dwDesiredAccess,
    BOOL     bInheritHandle,
    DWORD    dwOptions
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(48);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            HANDLE,
            HANDLE,
            LPHANDLE,
            DWORD,
            BOOL,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hSourceProcessHandle,
            hSourceHandle,
            hTargetProcessHandle,
            lpTargetHandle,
            dwDesiredAccess,
            bInheritHandle,
            dwOptions
        );
    }
    else {
        return FALSE;
    }

}

LPVOID l_VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(49);
    typedef LPVOID(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPVOID,
            SIZE_T,
            DWORD,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpAddress,
            dwSize,
            flAllocationType,
            flProtect
        );
    }
    else {
        return NULL;
    }

}

BOOL l_VirtualFree(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(50);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPVOID,
            SIZE_T,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpAddress,
            dwSize,
            dwFreeType
        );
    }
    else {
        return FALSE;
    }

}

void l_GetSystemInfo(
    LPSYSTEM_INFO lpSystemInfo
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(51);
    typedef void(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPSYSTEM_INFO
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpSystemInfo
        );
    }
    else {
        return;
    }

}

SIZE_T l_VirtualQuery(
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T                    dwLength
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(52);
    typedef SIZE_T(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCVOID,
            PMEMORY_BASIC_INFORMATION,
            SIZE_T
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpAddress,
            lpBuffer,
            dwLength
        );
    }
    else {
        return NULL;
    }

}

void l_ExitProcess(
    UINT uExitCode
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(53);
    typedef void(__stdcall* FUNCTION_POINTER_CAST)
        (
            UINT
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            uExitCode
        );
    }
    else {
        return;
    }

}

HANDLE l_GetCurrentThread(
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(54);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
        );
    }
    else {
        return NULL;
    }

}

BOOL l_GetComputerNameA(
    LPSTR   lpBuffer,
    LPDWORD nSize
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(55);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPSTR,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpBuffer,
            nSize
        );
    }
    else {
        return NULL;
    }

}

BOOL l_TerminateProcess(
    HANDLE hProcess,
    UINT   uExitCode
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(56);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            UINT
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            uExitCode
        );
    }
    else {
        return NULL;
    }

}


HANDLE l_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(57);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            DWORD,
            BOOL,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            dwDesiredAccess,
            bInheritHandle,
            dwProcessId
        );
    }
    else {
        return NULL;
    }

}

BOOL l_EnumProcesses(
    DWORD* lpidProcess,
    DWORD   cb,
    LPDWORD lpcbNeeded
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(58);

    if (function_pointer == NULL) function_pointer = get_function_pointer_psapi_dll(1);


    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            DWORD*,
            DWORD,
            LPDWORD
            );


    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpidProcess,
            cb,
            lpcbNeeded
        );
    }
    else {
        return NULL;
    }

}

BOOL l_GetExitCodeProcess(
    HANDLE  hProcess,
    LPDWORD lpExitCode
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(59);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lpExitCode
        );
    }
    else {
        return NULL;
    }

}

BOOL l_GetProcessTimes(
    HANDLE     hProcess,
    LPFILETIME lpCreationTime,
    LPFILETIME lpExitTime,
    LPFILETIME lpKernelTime,
    LPFILETIME lpUserTime
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(60);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPFILETIME,
            LPFILETIME,
            LPFILETIME,
            LPFILETIME
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lpCreationTime,
            lpExitTime,
            lpKernelTime,
            lpUserTime
        );
    }
    else {
        return NULL;
    }

}

BOOL l_EnumProcessModules(
    HANDLE  hProcess,
    HMODULE* lphModule,
    DWORD   cb,
    LPDWORD lpcbNeeded
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(61);


    if (function_pointer == NULL) function_pointer = get_function_pointer_psapi_dll(2);


    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            HMODULE*,
            DWORD,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lphModule,
            cb,
            lpcbNeeded
        );
    }
    else {
        return NULL;
    }

}

DWORD l_GetModuleFileNameExA(
    HANDLE  hProcess,
    HMODULE hModule,
    LPSTR   lpFilename,
    DWORD   nSize
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(62);

    if (function_pointer == NULL) function_pointer = get_function_pointer_psapi_dll(3);


    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            HMODULE,
            LPSTR,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            hModule,
            lpFilename,
            nSize
        );
    }
    else {
        return NULL;
    }

}

BOOL l_ReadProcessMemory(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesRead
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(63);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPCVOID,
            LPVOID,
            SIZE_T,
            SIZE_T*
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lpBaseAddress,
            lpBuffer,
            nSize,
            lpNumberOfBytesRead
        );
    }
    else {
        return NULL;
    }

}

BOOL l_WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(64);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPVOID,
            LPCVOID,
            SIZE_T,
            SIZE_T*
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lpBaseAddress,
            lpBuffer,
            nSize,
            lpNumberOfBytesWritten
        );
    }
    else {
        return NULL;
    }

}

DWORD l_GetModuleBaseNameA(
    HANDLE  hProcess,
    HMODULE hModule,
    LPSTR   lpBaseName,
    DWORD   nSize
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(65);

    if (function_pointer == NULL) function_pointer = get_function_pointer_psapi_dll(4);


    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            HMODULE,
            LPSTR,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            hModule,
            lpBaseName,
            nSize
        );
    }
    else {
        return 0;
    }

}

HANDLE l_CreateRemoteThread(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(66);

    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPSECURITY_ATTRIBUTES,
            SIZE_T,
            LPTHREAD_START_ROUTINE,
            LPVOID,
            DWORD,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hProcess,
            lpThreadAttributes,
            dwStackSize,
            lpStartAddress,
            lpParameter,
            dwCreationFlags,
            lpThreadId
        );
    }
    else {
        return NULL;
    }

}

BOOL l_GetThreadContext(
    HANDLE    hThread,
    LPCONTEXT lpContext
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(67);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPCONTEXT
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hThread,
            lpContext
        );
    }
    else {
        return NULL;
    }

}

BOOL l_SetThreadContext(
    HANDLE        hThread,
    const CONTEXT* lpContext
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(68);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            const CONTEXT*
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hThread,
            lpContext
        );
    }
    else {
        return NULL;
    }

}

LPVOID l_LockResource(
    HGLOBAL hResData
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(69);
    typedef LPVOID(__stdcall* FUNCTION_POINTER_CAST)
        (
            HGLOBAL
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hResData
        );
    }
    else {
        return NULL;
    }

}

HGLOBAL l_LoadResource(
    HMODULE hModule,
    HRSRC   hResInfo
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(70);
    typedef LPVOID(__stdcall* FUNCTION_POINTER_CAST)
        (
            HMODULE,
            HRSRC
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hModule,
            hResInfo
        );
    }
    else {
        return NULL;
    }

}

HRSRC l_FindResourceW(
    HMODULE hModule,
    LPWSTR  lpName,
    LPWSTR  lpType
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(71);
    typedef HRSRC(__stdcall* FUNCTION_POINTER_CAST)
        (
            HMODULE,
            LPWSTR,
            LPWSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hModule,
            lpName,
            lpType
        );
    }
    else {
        return NULL;
    }

}

DWORD l_SizeofResource(
    HMODULE hModule,
    HRSRC   hResInfo
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(72);
    typedef DWORD(__stdcall* FUNCTION_POINTER_CAST)
        (
            HMODULE,
            HRSRC
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hModule,
            hResInfo
        );
    }
    else {
        return NULL;
    }

}

HANDLE l_CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(73);
    typedef HANDLE(__stdcall* FUNCTION_POINTER_CAST)
        (
            DWORD ,
            DWORD 
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
             dwFlags,
             th32ProcessID
        );
    }
    else {
        return NULL;
    }

}

BOOL l_Process32First(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(74);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE           ,
            LPPROCESSENTRY32 
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
                       hSnapshot,
             lppe
        );
    }
    else {
        return false;
    }

}

BOOL l_Process32NextW(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_kernel32_dll(75);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            LPPROCESSENTRY32
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hSnapshot,
            lppe
        );
    }
    else {
        return false;
    }

}

// ntdll.dll
NTSTATUS l_NtTerminateProcess(
    HANDLE               ProcessHandle,
    NTSTATUS             ExitStatus
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(1);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            NTSTATUS
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ProcessHandle,
            ExitStatus
        );
    }
    else {
        return 0;
    }

}

NTSTATUS l_NtReadVirtualMemory(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    OUT PVOID               Buffer,
    IN ULONG                NumberOfBytesToRead,
    OUT PULONG              NumberOfBytesReaded
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(2);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            IN HANDLE,
            IN PVOID,
            OUT PVOID,
            IN ULONG,
            OUT PULONG
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ProcessHandle,
            BaseAddress,
            Buffer,
            NumberOfBytesToRead,
            NumberOfBytesReaded
        );
    }
    else {
        return 0;
    }

}


NTSTATUS l_NtWriteVirtualMemory(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritte
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(3);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            IN HANDLE,
            IN PVOID,
            IN PVOID,
            IN ULONG,
            OUT PULONG
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ProcessHandle,
            BaseAddress,
            Buffer,
            NumberOfBytesToWrite,
            NumberOfBytesWritte
        );
    }
    else {
        return 0;
    }

}

NTSTATUS l_NtGetContextThread(
    IN HANDLE               ThreadHandle,
    OUT PCONTEXT            pContex
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(4);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            IN HANDLE,
            OUT PCONTEXT
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ThreadHandle,
            pContex
        );
    }
    else {
        return 0;
    }

}


NTSTATUS l_NtSetContextThread(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(5);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            IN HANDLE,
            IN PCONTEXT
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ThreadHandle,
            Context
        );
    }
    else {
        return 0;
    }

}

NTSTATUS l_NtUnmapViewOfSection(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(6);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            IN HANDLE,
            IN PVOID
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ProcessHandle,
            BaseAddress
        );
    }
    else {
        return 0;
    }

}

NTSTATUS l_NtResumeThread(
    IN HANDLE               ThreadHandle,
    OUT PULONG              SuspendCount
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(7);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            IN HANDLE,
            OUT PULONG
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ThreadHandle,
            SuspendCount
        );
    }
    else {
        return 0;
    }

}

NTSTATUS l_NtClose(
    IN HANDLE Handle
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(8);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            IN HANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            Handle
        );
    }
    else {
        return 0;
    }

}

//
NTSTATUS l_NtQueryInformationProcess(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID           ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG          ReturnLength
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(9);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            PROCESSINFOCLASS,
            PVOID,
            ULONG,
            PULONG
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ProcessHandle,
            ProcessInformationClass,
            ProcessInformation,
            ProcessInformationLength,
            ReturnLength
        );
    }
    else {
        return 0;
    }

}

//
NTSTATUS l_RtlGetVersion(
    PRTL_OSVERSIONINFOW lpVersionInformation
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ntdll_dll(10);
    typedef NTSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            PRTL_OSVERSIONINFOW
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpVersionInformation
        );
    }
    else {
        return 0;
    }

}


// ole32.dll
HRESULT l_CoInitializeEx(
    LPVOID pvReserved,
    DWORD  dwCoInit
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ole32_dll(1);
    typedef HRESULT(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPVOID,
            DWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            pvReserved,
            dwCoInit
        );
    }
    else {
        return E_FAIL;
    }

}


void l_CoUninitialize(
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_ole32_dll(2);
    typedef void(__stdcall* FUNCTION_POINTER_CAST)
        (
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        function_pointer_cast(
        );
    }
    else {
        return;
    }

}


// shell32.dll
BOOL l_ShellExecuteExA(
    SHELLEXECUTEINFOA* pExecInfo
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_shell32_dll(1);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            SHELLEXECUTEINFOA*
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            pExecInfo
        );
    }
    else {
        return FALSE;
    }

}



// shlwapi.dll

BOOL l_PathFileExistsA(
    LPCSTR pszPath
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_shlwapi_dll(1);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            pszPath
        );
    }
    else {
        return FALSE;
    }

}


// advapi32.dll
LSTATUS l_RegOpenKeyExA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    DWORD  ulOptions,
    REGSAM samDesired,
    PHKEY  phkResult
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_advapi32_dll(1);
    typedef LSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            HKEY,
            LPCSTR,
            DWORD,
            REGSAM,
            PHKEY
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hKey,
            lpSubKey,
            ulOptions,
            samDesired,
            phkResult
        );
    }
    else {
        return FALSE;
    }

}

//
LSTATUS l_RegGetValueA(
    HKEY    hkey,
    LPCSTR  lpSubKey,
    LPCSTR  lpValue,
    DWORD   dwFlags,
    LPDWORD pdwType,
    PVOID   pvData,
    LPDWORD pcbData
)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_advapi32_dll(2);
    typedef LSTATUS(__stdcall* FUNCTION_POINTER_CAST)
        (
            HKEY,
            LPCSTR,
            LPCSTR,
            DWORD,
            LPDWORD,
            PVOID,
            LPDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            hkey,
            lpSubKey,
            lpValue,
            dwFlags,
            pdwType,
            pvData,
            pcbData
        );
    }
    else {
        return FALSE;
    }

}

//
BOOL l_GetUserNameA(
    LPSTR   lpBuffer,
    LPDWORD pcbBuffer

)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_advapi32_dll(3);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPSTR,
            LPDWORD

            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpBuffer,
            pcbBuffer

        );
    }
    else {
        return FALSE;
    }

}

//
BOOL l_OpenProcessToken(
    HANDLE  ProcessHandle,
    DWORD   DesiredAccess,
    PHANDLE TokenHandle

)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_advapi32_dll(4);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            DWORD,
            PHANDLE
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            ProcessHandle,
            DesiredAccess,
            TokenHandle
        );
    }
    else {
        return FALSE;
    }

}

BOOL l_LookupPrivilegeValueA(
    LPCSTR lpSystemName,
    LPCSTR lpName,
    PLUID  lpLuid

)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_advapi32_dll(5);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            LPCSTR lpSystemName,
            LPCSTR lpName,
            PLUID  lpLuid
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            lpSystemName,
            lpName,
            lpLuid
        );
    }
    else {
        return FALSE;
    }

}

BOOL l_AdjustTokenPrivileges(
    HANDLE            TokenHandle,
    BOOL              DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD             BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD            ReturnLength

)
{
    FARPROC function_pointer = NULL;

    function_pointer = get_function_pointer_advapi32_dll(6);
    typedef BOOL(__stdcall* FUNCTION_POINTER_CAST)
        (
            HANDLE,
            BOOL,
            PTOKEN_PRIVILEGES,
            DWORD,
            PTOKEN_PRIVILEGES,
            PDWORD
            );

    if (function_pointer != NULL) {

        FUNCTION_POINTER_CAST function_pointer_cast = (FUNCTION_POINTER_CAST)function_pointer;

        return function_pointer_cast(
            TokenHandle,
            DisableAllPrivileges,
            NewState,
            BufferLength,
            PreviousState,
            ReturnLength
        );
    }
    else {
        return FALSE;
    }

}