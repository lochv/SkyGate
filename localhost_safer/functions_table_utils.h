#pragma once

#include <Windows.h>

void get_function_pointer_helper(FARPROC* function_pointer, char* calling_function, HMODULE dll_hmodule, char* TARGET_FUNCTION_STR, int TARGET_FUNCTION_STR_LEN);

FARPROC get_function_pointer_kernel32_dll(int function_index);
FARPROC get_function_pointer_ole32_dll(int function_index);
FARPROC get_function_pointer_shell32_dll(int function_index);
FARPROC get_function_pointer_shlwapi_dll(int function_index);
FARPROC get_function_pointer_ntdll_dll(int function_index);
FARPROC get_function_pointer_wininet_dll(int function_index);
FARPROC get_function_pointer_ws2_32_dll(int function_index);
FARPROC get_function_pointer_advapi32_dll(int function_index);
FARPROC get_function_pointer_psapi_dll(int function_index);