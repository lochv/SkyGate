#pragma once


#include <winsock2.h>

class connection_tor 
{
public:
	static bool init_tor_socket(char* domain, SOCKET * param_socket);
};



