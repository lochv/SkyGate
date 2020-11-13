#pragma once

#include <windows.h>

bool check_admin();
bool disable_uac();
void install_driver();
BOOL Is64BitWindows();

bool write_file(char* filename, char* data, int data_size);
