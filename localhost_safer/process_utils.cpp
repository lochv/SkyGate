#include "process_utils.h"
#include <windows.h>

#include "global_config.h"
#include <stdio.h>

#include "debug.h"

#include <psapi.h>
#include <stdlib.h>

#include "common_utils.h"
#include "process_hollow.h"

#include "Winternl.h"

#include "functions_table.h"



#pragma warning(disable:4996)

bool init_process_injection_mutex(DWORD pid, PROCESS_INJECTION_MUTEX* process_injection_mutex)
{
	process_injection_mutex->pid = pid;

	//
	FILETIME data_create_time;
	LPFILETIME creation_time = &data_create_time;

	HANDLE targetProcess = l_OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (targetProcess == NULL) {
		DBG_MSG("init_process_injection_mutex() - l_OpenProcess(PROCESS_QUERY_INFORMATION) failed, error code: %d \n", l_GetLastError());
	}

	targetProcess = l_OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (targetProcess == NULL) {
		DBG_MSG("init_process_injection_mutex() - l_OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed, error code: %d, return now.\n", l_GetLastError());

		return false;
	}

	//
	DWORD process_exit_code = 0;

	bool get_process_exit_code = l_GetExitCodeProcess(targetProcess, &process_exit_code);

	if (!get_process_exit_code) {
		DBG_MSG("init_process_injection_mutex() - l_GetExitCodeProcess() failed, error code: %d. pid: %d. Return now. \n", l_GetLastError(), pid);
		return false;
	}

	//
	if (process_exit_code == STILL_ACTIVE) {
		DBG_MSG("init_process_injection_mutex() - process is STILL_ACTIVE. pid: %d \n", pid);
	}
	else {
		DBG_MSG("init_process_injection_mutex() - process is NOT STILL_ACTIVE. pid: %d. Return now. \n", pid);
		return false;
	}

	//
	DBG_MSG("init_process_injection_mutex() - l_GetProcessTimes() will be called.\n");
	FILETIME dont_use_1;
	FILETIME dont_use_2;
	FILETIME dont_use_3;

	bool get_time_ret = l_GetProcessTimes(
		targetProcess,
		creation_time,
		&dont_use_1,
		&dont_use_2,
		&dont_use_3
	);
	//

	if (!get_time_ret) {
		DBG_MSG("init_process_injection_mutex() - l_GetProcessTimes() failed, error code: %d, return now.\n", l_GetLastError());
		return false;
	}

	//
	DBG_MSG("init_process_injection_mutex() - l_GetProcessTimes(), creation_time->dwLowDateTime: %d\n", creation_time->dwLowDateTime);
	DBG_MSG("init_process_injection_mutex() - l_GetProcessTimes(), creation_time->dwHighDateTime: %d\n", creation_time->dwHighDateTime);


	//
	process_injection_mutex->create_time_dwLowDateTime = creation_time->dwLowDateTime;
	process_injection_mutex->create_time_dwHighDateTime = creation_time->dwHighDateTime;

	//
	DBG_MSG("init_process_injection_mutex() - SUCCESS.\n");
	return true;
}


//
bool operator==(const PROCESS_INJECTION_MUTEX& x, const PROCESS_INJECTION_MUTEX& y)
{
	DBG_MSG("Compare 2 PROCESS_INJECTION_MUTEXs \n");
	
	//
	DBG_MSG("x.pid: %d, y.pid: %d\n", x.pid, y.pid);
	DBG_MSG("x.create_time_dwLowDateTime: %d, y.create_time_dwLowDateTime: %d\n", x.create_time_dwLowDateTime, y.create_time_dwLowDateTime);
	DBG_MSG("x.create_time_dwHighDateTime: %d, y.create_time_dwHighDateTime: %d\n", x.create_time_dwHighDateTime, y.create_time_dwHighDateTime);

	if (x.pid != y.pid) return false;
	if (x.create_time_dwLowDateTime != y.create_time_dwLowDateTime) return false;
	if (x.create_time_dwHighDateTime != y.create_time_dwHighDateTime) return false;

	//
	return true;

}


//
/* Utility function to insert a node at the beginning */
void push_node_to_list(struct node** head_ref, DWORD pid, DWORD create_time_dwLowDateTime, DWORD create_time_dwHighDateTime)
{
	struct node* new_node = (struct node*)calloc(sizeof(struct node), 1);

	new_node->pid = pid;
	new_node->create_time_dwLowDateTime = create_time_dwLowDateTime;
	new_node->create_time_dwHighDateTime = create_time_dwHighDateTime;

	new_node->next = *head_ref;

	*head_ref = new_node;
}

void push_node_to_list(struct node** head_ref, struct node * new_node)
{
	new_node->next = *head_ref;

	*head_ref = new_node;
}

// find a node by data
struct node * find_node_in_list(struct node* head, struct node n)
{
	while (head != NULL)
	{
		if (*head == n)
		{
			return head;
		}

		head = head->next;
	}

	return NULL;
}

void delete_node_in_list(struct node ** head_ref, struct node* n)
{
	//
	DBG_MSG("delete_node_in_list() called.\n");

	//
	if (n == NULL) {
		DBG_MSG("delete_node_in_list() - to be deleted node is NULL. Return now. \n");
		return;
	}

	//
	if (*head_ref == NULL) {
		DBG_MSG("delete_node_in_list() - list is NULL. Return now. \n");
		return;
	}


	// When node to be deleted is head node 
	if ((*head_ref) == n)
	{
		if ((*head_ref)->next == NULL)
		{
			DBG_MSG("delete_node_in_list() - There is only one node.\n");

			free((*head_ref));
			(*head_ref) = NULL;

			DBG_MSG("delete_node_in_list() - node deleted.\n");

			return;
		}
		else
		{
			/* Copy the data of next node to head */
			(*head_ref)->pid = (*head_ref)->next->pid;
			(*head_ref)->create_time_dwLowDateTime = (*head_ref)->next->create_time_dwLowDateTime;
			(*head_ref)->create_time_dwHighDateTime = (*head_ref)->next->create_time_dwHighDateTime;

			// store address of next node 
			n = (*head_ref)->next;

			// Remove the link of next node 
			(*head_ref)->next = (*head_ref)->next->next;

			// free memory 
			free(n);

			DBG_MSG("delete_node_in_list() - node deleted.\n");

			return;
		}
	}


	// When not first node, follow the normal deletion process 

	// find the previous node 
	struct node* prev = (*head_ref);
	
	while (prev->next != NULL && prev->next != n) 
	{
		prev = prev->next;
	}
		
	// Check if node really exists in Linked List 
	if (prev->next == NULL)
	{
		DBG_MSG("delete_node_in_list() - Given node is not present in Linked List.\n");
		return;
	}

	// Remove node from Linked List 
	prev->next = prev->next->next;

	// Free memory 
	free(n);

	DBG_MSG("delete_node_in_list() - node deleted.\n");
	return;
}

// value copy link list
void copy_list(struct node ** dest_head_ref, struct node * source_head)
{
	while (source_head != NULL) 
	{
		struct node * new_node = (struct node *)calloc(sizeof(struct node), 1);

		new_node->pid = source_head->pid;
		new_node->create_time_dwLowDateTime = source_head->create_time_dwLowDateTime;
		new_node->create_time_dwHighDateTime = source_head->create_time_dwHighDateTime;

		push_node_to_list(dest_head_ref, new_node);

		source_head = source_head->next;
	}
}

//
void delete_list(struct node ** head_ref)
{
	while (*head_ref != NULL) 
	{
		struct node* tmp = (*head_ref)->next;

		free(*head_ref);

		*head_ref = tmp;
	}
}


// remove dead process from the list
void remove_dead_processes_from_list(struct node** head)
{
	struct node* tmp_list = NULL;

	copy_list(&tmp_list, *head);

	DBG_MSG("tmp_list:\n");
	print_list(tmp_list);

	DBG_MSG("head:\n");
	print_list(*head);

	while (tmp_list != NULL) 
	{
		DBG_MSG("remove_dead_processes_from_list() - checking process_id: %d \n", tmp_list->pid);

		if (tmp_list->pid == 0)
		{
			DBG_MSG("remove_dead_processes_from_list() - process with id of Zero, so, we continue.\n");
			goto CONTINUE_LOOP;
		}

		//
		// 1. check if process is still existed, if NOT, remvove it.
		// WARN: could not guarantee OpenProcess() in step 2 does the job, since, although the process has gone, the process handle may still existed, and OpenProcess() always cuccess,
		// after the process has exitted.
		HANDLE targetProcess = l_OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, tmp_list->pid);

		if (targetProcess == NULL) {
			DBG_MSG("remove_dead_processes_from_list() - OpenProcess(PROCESS_QUERY_INFORMATION) failed, error code: %d. pid: %d\n", l_GetLastError(), tmp_list->pid);
		}

		targetProcess = l_OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, tmp_list->pid);

		if (targetProcess == NULL) {
			DBG_MSG("remove_dead_processes_from_list() - OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed, error code: %d. pid: %d \n", l_GetLastError(), tmp_list->pid);

			DBG_MSG("remove_dead_processes_from_list() - removing process_id: %d from the list and continute.\n", tmp_list->pid);
			
			//
			delete_node_in_list(head, find_node_in_list(*head, *tmp_list) );

			goto CONTINUE_LOOP;
		}

		//
		DWORD process_exit_code = 0;

		bool get_process_exit_code = l_GetExitCodeProcess(targetProcess, &process_exit_code);

		if (!get_process_exit_code) {
			DBG_MSG("remove_dead_processes_from_list() - GetExitCodeProcess() failed, error code: %d. pid: %d \n", l_GetLastError(), tmp_list->pid);

			DBG_MSG("remove_dead_processes_from_list() - removing process_id: %d from the list and continute.\n", tmp_list->pid);
			
			//
			delete_node_in_list(head, find_node_in_list(*head, *tmp_list) );

			goto CONTINUE_LOOP;
		}

		//
		if (process_exit_code == STILL_ACTIVE) {
			DBG_MSG("remove_dead_processes_from_list() - process is STILL_ACTIVE. pid: %d \n", tmp_list->pid);
		}
		else {
			DBG_MSG("remove_dead_processes_from_list() - process is NOT STILL_ACTIVE. pid: %d \n", tmp_list->pid);

			DBG_MSG("remove_dead_processes_from_list() - removing process_id: %d from the list and continute.\n", tmp_list->pid);
			
			//
			delete_node_in_list(head, find_node_in_list(*head, *tmp_list) );

			goto CONTINUE_LOOP;
		}

		// 2.
		PROCESS_INJECTION_MUTEX new_pit;

		bool ret_init_new_pit = init_process_injection_mutex(tmp_list->pid, &new_pit);

		if (!ret_init_new_pit) {
			// remove from list, don't care of any reason.
			DBG_MSG("remove_dead_processes_from_list() - init_process_injection_mutex() failed, removing process_id: %d from the list.\n", tmp_list->pid);
			DBG_MSG("remove_dead_processes_from_list() - checking process_id: %d done.\n", tmp_list->pid);
			
			//
			delete_node_in_list(head, find_node_in_list(*head, *tmp_list) );

			goto CONTINUE_LOOP;
		}

		if (!(new_pit == *tmp_list)) {
			DBG_MSG("remove_dead_processes_from_list() - old process_injection_mutex is DIFFER from new one, removing process_id: %d from the list.\n", tmp_list->pid);
			DBG_MSG("remove_dead_processes_from_list() - checking process_id: %d done.\n", tmp_list->pid);
			
			//
			delete_node_in_list(head, find_node_in_list(*head, *tmp_list) );

			goto CONTINUE_LOOP;
		}

		//
CONTINUE_LOOP:
		tmp_list = tmp_list->next;
	}

	delete_list(&tmp_list);
}



/* Utility function to print a linked list */
void print_list(struct node* head)
{
	while (head != NULL)
	{
		DBG_MSG("node info:\n");
		DBG_MSG("pid: %d \n", head->pid);
		DBG_MSG("create_time_dwLowDateTime: %d \n", head->create_time_dwLowDateTime);
		DBG_MSG("create_time_dwHighDateTime: %d \n\n", head->create_time_dwHighDateTime);
		head = head->next;
	}
}

// free yourself
char* get_process_name(DWORD pid)
{
	HANDLE Handle = l_OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		pid
	);


	if (Handle)
	{
		char* process_name = (char*)calloc(MAX_PATH, 1);

		if (l_GetModuleFileNameExA(Handle, 0, process_name, MAX_PATH))
		{
			// At this point, buffer contains the full path to the executable
			// free it yourself.
			return process_name;
		}
		else
		{
			// You better call l_GetLastError() here
			DBG_MSG("get_process_name() - process_name: %s \n", process_name);
			return NULL;
		}

		l_CloseHandle(Handle);
	}
}



char* get_process_command_line(DWORD pid)
{
	HANDLE processHandle;
	PVOID pebAddress;
	PVOID rtlUserProcParamsAddress;
	UNICODE_STRING commandLine;
	WCHAR* commandLineContents;

	if (
		(processHandle = l_OpenProcess
		(
			PROCESS_QUERY_INFORMATION | /* required for NtQueryInformationProcess */
			PROCESS_VM_READ, /* required for l_ReadProcessMemory */
			FALSE, pid)) == 0
		)
	{
		DBG_MSG("get_process_command_line() - l_OpenProcess() failed, error code: %d \n", l_GetLastError());
		return NULL;
	}

	pebAddress = (PVOID)get_targeted_exe_PEB(processHandle);

	/* get the address of ProcessParameters */
	if (!l_ReadProcessMemory(processHandle,
		&(((_PEB*)pebAddress)->ProcessParameters),
		&rtlUserProcParamsAddress,
		sizeof(PVOID), NULL))
	{
		DBG_MSG("get_process_command_line() - l_ReadProcessMemory() - get the address of ProcessParameters failed, error code: %d \n", l_GetLastError());
		return NULL;
	}

	/* read the CommandLine UNICODE_STRING structure */
	if (!l_ReadProcessMemory(processHandle,
		&(((_RTL_USER_PROCESS_PARAMETERS*)rtlUserProcParamsAddress)->CommandLine),
		&commandLine, sizeof(commandLine), NULL))
	{
		DBG_MSG("get_process_command_line() - l_ReadProcessMemory() -  read the CommandLine UNICODE_STRING structure failed, error code: %d \n", l_GetLastError());
		return NULL;;
	}

	/* allocate memory to hold the command line */
	commandLineContents = (WCHAR*)calloc(commandLine.Length, 1);

	/* read the command line */
	if (!l_ReadProcessMemory(processHandle, commandLine.Buffer,
		commandLineContents, commandLine.Length, NULL))
	{
		DBG_MSG("get_process_command_line() - l_ReadProcessMemory() -  read the command line  failed, error code: %d \n", l_GetLastError());
		return NULL;;
	}

	char* command_line = (char*)calloc(1000, 1);

	wcstombs(command_line, commandLineContents, 1000);

	free(commandLineContents);

	l_CloseHandle(processHandle);

	// free yourself
	return command_line;
}

DWORD get_process_id_by_name(char* process_name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = l_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (l_Process32First(snapshot, &entry) == TRUE)
	{
		char* exe = (char*)calloc(sizeof(entry.szExeFile) * 2, 1);
		wtoc(exe, entry.szExeFile);

		DBG_MSG("get_process_id_by_name() - exe: %s \n", exe);

		if (_stricmp(exe, process_name) == 0)
		{
			DBG_MSG("get_process_id_by_name() - found pid: %d \n", entry.th32ProcessID);

			free(exe);
			l_CloseHandle(snapshot);

			return entry.th32ProcessID;
		}

		free(exe);

		///
		while (l_Process32NextW(snapshot, &entry) == TRUE)
		{
			char* exe = (char*)calloc(sizeof(entry.szExeFile) * 2, 1);
			wtoc(exe, entry.szExeFile);

			DBG_MSG("get_process_id_by_name() - exe: %s \n", exe);

			if (_stricmp(exe, process_name) == 0)
			{
				DBG_MSG("get_process_id_by_name() - found pid: %d \n", entry.th32ProcessID);

				free(exe);
				l_CloseHandle(snapshot);

				return entry.th32ProcessID;
			}

			free(exe);
		}
	}

	DBG_MSG("get_process_id_by_name() - process NOT found.\n");
	l_CloseHandle(snapshot);
	return 0;
}

/*
DWORD get_process_id_by_name(char * process_name)
{
	DBG_MSG("get_process_id_by_name() - Searching for: %s\n", process_name);

	char szProcessName[MAX_PATH];

	//
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!l_EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}


	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			///
			HANDLE hProcess = l_OpenProcess(PROCESS_QUERY_INFORMATION |
				PROCESS_VM_READ,
				FALSE, aProcesses[i]);

			// Get the process name.

			if (NULL != hProcess)
			{
				//
				DWORD process_exit_code = 0;

				bool get_process_exit_code = l_GetExitCodeProcess(hProcess, &process_exit_code);

				if (!get_process_exit_code) {
					DBG_MSG("get_process_id_by_name() - GetExitCodeProcess() failed, error code: %d. pid: %d. Return now. \n", l_GetLastError(), aProcesses[i]);
					return false;
				}

				//
				if (process_exit_code == STILL_ACTIVE) {
					DBG_MSG("get_process_id_by_name() - process is STILL_ACTIVE. pid: %d \n", aProcesses[i]);
				}
				else {
					DBG_MSG("get_process_id_by_name() - process is NOT STILL_ACTIVE. pid: %d. Return now. \n", aProcesses[i]);
					return false;
				}

				//
				HMODULE hMod;
				DWORD cbNeeded;

				if (l_EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
				{

					// TODO: cause crash in release build, so this get_process_id_by_name() function is not used.
					l_GetModuleBaseNameA(hProcess, hMod, szProcessName, MAX_PATH);

					DBG_MSG("get_process_id_by_name() - current szProcessName: %s\n", szProcessName);

					if ( _stricmp(szProcessName, process_name) ==0 ) {
						DBG_MSG("get_process_id_by_name() - FOUND with process id: %d , return now.\n", aProcesses[i] );

						return aProcesses[i];
					}
				}
			}


			///
		}
	}

	DBG_MSG("get_process_id_by_name() - process name: %s NOT FOUND.\n", process_name);

	return 0;
}
*/