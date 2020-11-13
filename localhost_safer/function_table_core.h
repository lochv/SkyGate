#pragma once

#include <windows.h>

FARPROC l_GetProcAddress(
    HMODULE hModule,
    LPCSTR  lpProcName
);

HMODULE l_LoadLibraryA(
    LPCSTR lpLibFileName
);

HMODULE l_GetModuleHandleA(
    LPCSTR lpModuleName
);

HMODULE _getKernel32Handle(void);