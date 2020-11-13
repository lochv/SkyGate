#pragma once

#include <windows.h>

void injection_debug_message(char* str_and_format);

void injection_debug_message(char* str_and_format, void* param);
void injection_debug_message(char* str_and_format, int param);
void injection_debug_message(char* str_and_format, DWORD param);
void injection_debug_message(char* str_and_format, char* param);
void injection_debug_message(char* str_and_format, HANDLE param);

void injection_debug_message(char* str_and_format, int param_1, int param_2);
void injection_debug_message(char* str_and_format, DWORD param_1, char* param_2);
void injection_debug_message(char* str_and_format, char* param_1, DWORD param_2);
void injection_debug_message(char* str_and_format, char* param_1, char* param_2);

void injection_debug_message(char* str_and_format, PVOID param_1, SIZE_T param_2);
void injection_debug_message(char* str_and_format, PVOID param_1, SIZE_T param_2, DWORD param_3);
void injection_debug_message(char* str_and_format, size_t param_1, SIZE_T param_2, SIZE_T param_3);

void injection_debug_message(char* str_and_format, char* param_1, char* param_2, FARPROC param_3);

void injection_debug_message(char* str_and_format, char* param_1, char* param_2, int param_3);