#include <strsafe.h>
#include <stdlib.h>
#include <windows.h>

#include "global_config.h"

//
void injection_debug_message(char* str_and_format)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format);

	OutputDebugStringA(buffer);

	free(buffer);
}

//
void injection_debug_message(char* str_and_format, void* param)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param);

	OutputDebugStringA(buffer);

	free(buffer);
}

//
void injection_debug_message(char* str_and_format, int param)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param);

	OutputDebugStringA(buffer);

	free(buffer);
}

//
void injection_debug_message(char* str_and_format, DWORD param)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param);

	OutputDebugStringA(buffer);

	free(buffer);
}

//
void injection_debug_message(char* str_and_format, char* param)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param);

	OutputDebugStringA(buffer);

	free(buffer);
}

//
/*
void injection_debug_message(char* str_and_format, HANDLE param)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param);

	OutputDebugStringA(buffer);

	free(buffer);
}
*/

//
void injection_debug_message(char* str_and_format, int param_1, int param_2)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2);

	OutputDebugStringA(buffer);

	free(buffer);
}

//
void injection_debug_message(char* str_and_format, char* param_1, DWORD param_2)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2);

	OutputDebugStringA(buffer);

	free(buffer);
}



//
void injection_debug_message(char* str_and_format, PVOID param_1, SIZE_T param_2)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2);

	OutputDebugStringA(buffer);

	free(buffer);
}

//
void injection_debug_message(char* str_and_format, char* param_1, char* param_2)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2);

	OutputDebugStringA(buffer);

	free(buffer);
}

//
void injection_debug_message(char* str_and_format, PVOID param_1, SIZE_T param_2, DWORD param_3)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2, param_3);

	OutputDebugStringA(buffer);

	free(buffer);
}

void injection_debug_message(char* str_and_format, size_t param_1, SIZE_T param_2, SIZE_T param_3)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2, param_3);

	OutputDebugStringA(buffer);

	free(buffer);
}

void injection_debug_message(char* str_and_format, DWORD param_1, char* param_2)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2);

	OutputDebugStringA(buffer);

	free(buffer);
}

void injection_debug_message(char* str_and_format, char* param_1, char* param_2, FARPROC param_3)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2, param_3);

	OutputDebugStringA(buffer);

	free(buffer);
}

void injection_debug_message(char* str_and_format, char* param_1, char* param_2, int param_3)
{
	char* buffer = (char*)calloc(MAX_INJECTION_DEBUG_MESSAGE_LEN, 1);

	StringCbPrintfA(buffer, MAX_INJECTION_DEBUG_MESSAGE_LEN, str_and_format, param_1, param_2, param_3);

	OutputDebugStringA(buffer);

	free(buffer);
}
