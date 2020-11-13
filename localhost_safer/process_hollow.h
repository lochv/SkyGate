#pragma once

#include <windows.h>

//int CreateHollowedProcess(char* pDestCmdLine, char pBuffer[]);

int create_hollowed_proc(const char* name, char* cmd_line, void* map, DWORD* tor_process_id);
int ph_init(void);

const void* get_targeted_exe_PEB(HANDLE proc);