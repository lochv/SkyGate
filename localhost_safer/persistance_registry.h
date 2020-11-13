#pragma once
#include <windows.h>

BOOL IsMyProgramRegisteredForStartup(char* pszAppName);
BOOL run_and_runonce(char* pszAppName, char* pathToExe, char* args, int run_type);

