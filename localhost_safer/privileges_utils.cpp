#include "privilege_utils.h"
#include <windows.h>

#include "global_config.h"
#include <stdio.h>

#include "debug.h"

#include "functions_table.h"

/*
Enable a privilege for the current process
*/

BOOL enable_windows_privilege(char * privilege)
{
	HANDLE token;
	TOKEN_PRIVILEGES priv;
	BOOL ret = FALSE;

	DBG_MSG("enable_windows_privilege() - Enable %s privilege\n", privilege);

	//
	int error_code = 0;

	if (l_OpenProcessToken(l_GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) 
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (l_LookupPrivilegeValueA(NULL, privilege, &priv.Privileges[0].Luid) != FALSE)
		{
			if (l_AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE) 
			{
				ret = TRUE;

				if (l_GetLastError() == ERROR_NOT_ALL_ASSIGNED) // In case privilege is not part of token (ex run as non admin)
				{
					DBG_MSG("enable_windows_privilege() - AdjustTokenPrivileges() failed, error code: ERROR_NOT_ALL_ASSIGNED. Process run as non admin.\n");
					ret = FALSE;
				}
			} 
			else {
				DBG_MSG("enable_windows_privilege() - AdjustTokenPrivileges() failed, error code: %d.\n", l_GetLastError());
			}
			
		}
		else {
			DBG_MSG("enable_windows_privilege() - LookupPrivilegeValueA() failed, error code: %d.\n", l_GetLastError());
		}

		
		l_CloseHandle(token);
	}
	else {
		DBG_MSG("enable_windows_privilege() - OpenProcessToken() failed, error code: %d.\n", l_GetLastError());
	}
	
	if (ret == TRUE) {
		DBG_MSG("enable_windows_privilege() - SUCCESS.\n");
	}
	else {
		DBG_MSG("enable_windows_privilege() - FAILED.\n");
	}
		

	return ret;
}