

/*
Guide is here: https://nytrosecurity.com/2018/02/26/hooking-chromes-ssl-functions/

Printed to pdf.

*/

#include <windows.h>
#include <psapi.h>
#include "global_config.h"
#include "debug.h"


#include "functions_table.h"

#include "crypto.h"

#pragma warning(disable:4996)

bool is_version_string(char * str)
{
    for (int i = 0; i < strlen(str); i++) {
        if ((str[i] >= 0x30 && str[i] <= 0x39) || (str[i] == 0x2e)) {
            continue;
        }
        else {
            return false;
        }
    }

    return true;
}

// free() yourself
char * get_chrome_version(DWORD processID)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.

    DBG_MSG("\nProcess ID: %u\n", processID);

    // Get a handle to the process.

    hProcess = l_OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
        return NULL;

    // Get a list of all the modules in this process.
    if (l_EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            char szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (l_GetModuleFileNameExA(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.

                char* decrypted_str_1 = NULL;

                decrypt_to_string(&decrypted_str_1, CHROME_DLL_STR, CHROME_DLL_STR_LEN);

                if (strstr(szModName, decrypted_str_1) != NULL) {
                    DBG_MSG("get_chrome_version() - found chrome.dll module full name: %s \n", szModName);

                    char* token = strtok(szModName, "\\");

                    // loop through the string to extract all other tokens
                    while (token != NULL) {
                        if (is_version_string(token)) {
                            DBG_MSG("get_chrome_version() - Found version string, version: %s \n", token);

                            char* version = (char*)calloc(50, 1);

                            strcpy(version, token);

                            l_CloseHandle(hProcess);

                            //
                            free(decrypted_str_1);

                            // free it yourself
                            return version;
                        }

                        token = strtok(NULL, "\\");
                    }

                    //
                }

                free(decrypted_str_1);
            }
        }
    }

    // Release the handle to the process.

    l_CloseHandle(hProcess);
    return NULL;
}
