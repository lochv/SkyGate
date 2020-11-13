#pragma once



#include <windows.h>



#include <shellapi.h>



char* read_file_to_buffer(char* pSourceFile);
bool write_file(char* filename, char* data, int data_size);

SHELLEXECUTEINFOA * open_or_runas_executor(char* command_line, BOOL runas_flag);

void load_program_resource(char** resource_bytes, LPWSTR resource_id, DWORD* resource_size);

BOOL Is64BitWindows();
WORD GetVersionWord();
BOOL IsWin8OrHigher();
BOOL IsVistaOrHigher();


RTL_OSVERSIONINFOW * GetRealOSVersion();

void wtoc(CHAR* Dest, const WCHAR* Source);

bool get_pc_guid(char* value);

bool getmyipaddress(char* buffer);

char* generate_alpha_numeric_string(int len);