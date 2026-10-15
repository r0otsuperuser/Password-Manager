#ifndef BACKEND_H
#define BACKEND_H
#define AUTH_TOKEN_BYTES 32
#define VAULT_PATH "vault.db"

#include <stddef.h>

int domain_extract(const char* url, char* bf, size_t bf_len);
int validate(unsigned char* key, unsigned char* salt, unsigned char* nonce);
int load_token(unsigned char* token);
int native_server(void);
int validate_with_password(const char* master, unsigned char* key,
    unsigned char* salt, unsigned char* nonce);


#endif