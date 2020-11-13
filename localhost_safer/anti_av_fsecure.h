#pragma once

/*
Bypass Windows defender runtime scan when suspect API(s) is called.

see:
	https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/

	https://github.com/FSecureLABS/Ninjasploit/tree/master/c/meterpreter/source/extensions/ninjasploit


*/

#include <windows.h>

void fsecure_windows_defender_runtime_suspect_apis_call_bypass(HANDLE * main_thread_handle, PVOID memory_start_address, DWORD memory_size);
