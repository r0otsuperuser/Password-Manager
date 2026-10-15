#include "backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>
#include <sqlite3.h>
#include <ctype.h>

#define MAX 256
#define MAX_CREDENTIALS 1024

typedef struct {
    char site[MAX];
    char username[MAX];
    char password[MAX];
} CredentialRecord;


static int get_credential(char *domain, char*bf_user, char* bf_pass, unsigned char* key) {
    sqlite3* db;
    sqlite3_stmt* stmt = NULL;
    CredentialRecord *cred = NULL;
    int result = -1; 

    int rc = sqlite3_open(VAULT_PATH, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1; 
    }

    const char *sql =
        "SELECT nonce, ciphertext "
        "FROM credentials "
        "ORDER BY id;";

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }

    cred = calloc(MAX_CREDENTIALS, sizeof(CredentialRecord));
    if (cred == NULL) {
        fprintf(stderr, "Error: failed to allocate memory.\n");
        result = -3;
        goto cleanup; 
    }

    int count = 0;

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && count < MAX_CREDENTIALS) {
        const unsigned char *nonce = sqlite3_column_blob(stmt, 0);
        const unsigned char *ciphertext = sqlite3_column_blob(stmt, 1);
        int nonce_len = sqlite3_column_bytes(stmt, 0);
        int ciphertext_len = sqlite3_column_bytes(stmt, 1);

        if (nonce_len != crypto_secretbox_NONCEBYTES || ciphertext_len <= crypto_secretbox_MACBYTES) {
            continue;
        }

        unsigned char plaintext[MAX *3 +1] = {0};
        int plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES;

        if (plaintext_len >= (int) sizeof(plaintext)) continue;

        if (crypto_secretbox_open_easy(
            plaintext,
            ciphertext,
            ciphertext_len,
            nonce,
            key
        ) != 0) {
            sodium_memzero(plaintext, sizeof(plaintext));
            continue;
        }

        plaintext[plaintext_len] = '\0';

        char* site = strstr((char*) plaintext, "site=");
        char* username = strstr((char*) plaintext, "username=");
        char* password = strstr((char*) plaintext, "password=");

        if (site != NULL && username != NULL && password != NULL) {
            site += strlen("site=");
            username += strlen("username=");
            password += strlen("password=");

            site[strcspn(site, "\n")] = '\0';
            username[strcspn(username, "\n")] = '\0';
            password[strcspn(password, "\n")] = '\0';

            snprintf(cred[count].site, sizeof(cred[count].site), "%s", site);
            snprintf(cred[count].username, sizeof(cred[count].username), "%s", username);
            snprintf(cred[count].password, sizeof(cred[count].password), "%s", password);

            count++;
        }

        sodium_memzero(plaintext, sizeof(plaintext));
    }

    sqlite3_finalize(stmt);
    stmt = NULL;
    sqlite3_close(db);
    db = NULL;

    if (rc != SQLITE_DONE) {
        result = -1;
        goto cleanup;
    }

    if (count == 0) {
        fprintf(stderr, "No credentials found.\n");
        result = -2;
        goto cleanup;
    }

    result = 0; // default: domain not found
    for (int i=0; i<count; i++) {
        if (strcmp(cred[i].site, domain) == 0) {
            memcpy(bf_user, cred[i].username, strlen(cred[i].username) +1);
            memcpy(bf_pass, cred[i].password, strlen(cred[i].password) +1);
            result = 1;
            break;
        }
    }

cleanup:
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    if (cred) {
        sodium_memzero(cred, MAX_CREDENTIALS * sizeof(CredentialRecord));
        free(cred);
    }
    return result;
}

static int json_extract(const char* json, const char* key, char* bf, size_t bf_size) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char* json_key = strstr(json, pattern);
    if (!json_key) return 0;

    const char* colon = strchr(json_key, ':');
    if (!colon) return 0;
    
    const char* first_char = strchr(colon, '"');
    if (!first_char) return 0;
    first_char++;

    const char* json_value = first_char;
    
    size_t j = 0;
    while (*json_value != '\0' && *json_value != '"') {
        if (*json_value == '\\') {
            json_value++;
            if (*json_value == '\0') return 0;

            char c;
            switch (*json_value) {
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'u': {
                    if (!isxdigit((unsigned char) json_value[1]) || !isxdigit((unsigned char) json_value[2]) ||
                        !isxdigit((unsigned char) json_value[3]) || !isxdigit((unsigned char) json_value[4])) {
                        return 0;    
                    }

                    char hex[5] = {json_value[1], json_value[2], json_value[3], json_value[4], '\0'};
                    long cp = strtol(hex, NULL, 16);
                    json_value += 4;

                    // Limitation: \uXXXX escapes above 0x7F are rejected (no UTF-8 encoding
                    // of code points). Raw UTF-8 bytes in the JSON are copied through as-is.
                    if (cp >= 0x80) return 0;
                    c = (char) cp;
                    break;
                }
                default:
                    return 0;

            }

            if (j >= bf_size -1) return 0;
            bf[j++] = c;
            json_value++;

        } else {
            if (j >= bf_size -1) return 0;
            bf[j++] = *json_value++;
        }
    }
    
    if (*json_value != '"') return 0;

    bf[j] = '\0';
    return 1;
}

int domain_extract(const char* url, char* bf, size_t bf_len) {
    const char *being = url;
    const char *sep;

    sep = strstr(being, "://");

    if (sep != NULL) being = sep +3;

    size_t len = 0;
    while (being[len] != '\0' &&
        being[len] != ':' &&
        being[len] != '?' &&
        being[len] != '#' &&
        being[len] != '/') {
        len++;
    }

    if (len >= bf_len) len = bf_len -1;

    memcpy(bf, being, len);
    bf[len] = '\0';
    
    return 1;
}

static int json_escape(const char* cred, char* out, size_t out_size) {
    size_t j = 0;

    for (size_t i = 0; cred[i] != '\0'; i++) {
        unsigned char c = (unsigned char) cred[i];
        const char* esc = NULL;
        char buf[7];

        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            default:
                if (c < 0x20) {
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    esc = buf;
                }
        }

        size_t len = esc ? strlen(esc) : 1;
        if (j + len >= out_size) return -1;

        if (esc) {
            memcpy(out + j, esc, len);
        } else {
            out[j] = (char) c;
        }
        j += len;
    }

    if (j >= out_size) return -1;
    out[j] = '\0';
    return (int) j;
}

static ssize_t read_full(int fd, void* bf, size_t count) {
    size_t total = 0;
    while (total < count) {
        // Loop because read() may return fewer bytes than requested (e.g. on pipes).
        ssize_t n = read(fd, (char*)bf + total, count - total);
        if (n <= 0) return n;
        total += (size_t) n;
    }
    return (ssize_t) total;
}

static ssize_t write_full(int fd, const void* buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t n = write(fd, (const char*)buf + total, count - total);
        if (n <= 0) return n;
        total += (size_t) n;
    }
    return (ssize_t) total;
}

static int read_message(char** out_json) {
    uint32_t len = 0; // Native Messaging framing: 4-byte length prefix, then the JSON payload

    if (read_full(0, &len, sizeof(len)) != (ssize_t) sizeof(len)) return 0;

    if (len == 0 || len > 1024*1024) return 0; // cap message size at 1 MB to bound the allocation

    char* buf = malloc((size_t) len + 1); // +1 for the NUL terminator
    if (!buf) return 0;

    if (read_full(0, buf, len) != (ssize_t) len) {
        free(buf);
        return 0;
    }

    buf[len] = '\0';
    *out_json = buf;
    return 1;
}

static int write_message(const char* json) {
    uint32_t len = (uint32_t) strlen(json);

    if (write_full(1, &len, sizeof(len)) != (ssize_t) sizeof(len)) return 0;
    if (write_full(1, json, len) != (ssize_t) len) return 0;

    return 1;
}

int native_server(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium error.\n");
        return 0;
    }

    char* msg = NULL;
    if (!read_message(&msg)) return 0;

    char action[32] = {0};
    char master[2048] = {0};
    char token_hex[AUTH_TOKEN_BYTES * 2 + 1] = {0};

    json_extract(msg, "action", action, sizeof(action));
    json_extract(msg, "master_password", master, sizeof(master));
    json_extract(msg, "auth_token", token_hex, sizeof(token_hex));

    sodium_memzero(msg, strlen(msg));
    free(msg);

    if (strcmp(action, "unlock") != 0) {
        write_message("{\"error\":\"expected unlock action\"}");
        sodium_memzero(master, sizeof(master));
        sodium_memzero(token_hex, sizeof(token_hex));
        return 0;
    }

    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    // Defense in depth: the token still blocks unauthorized callers if the browser's
    // allowed_origins check fails or the extension ID is misconfigured.
    unsigned char stored_hash[AUTH_TOKEN_BYTES];
    if (!load_token(stored_hash)) {
        write_message("{\"error\":\"could not load auth token\"}");
        sodium_memzero(master, sizeof(master));
        sodium_memzero(token_hex, sizeof(token_hex));
        return 0;
    }

    unsigned char provided_hash[AUTH_TOKEN_BYTES];
    unsigned char provided_token[AUTH_TOKEN_BYTES];
    size_t provided_len = 0;
    int token_ok = 0;

    if (sodium_hex2bin(provided_token, sizeof(provided_token), token_hex, strlen(token_hex),
        NULL, &provided_len, NULL) == 0 && provided_len == sizeof(provided_token)) {

        crypto_generichash(provided_hash, sizeof(provided_hash), provided_token, sizeof(provided_token),
        NULL, 0);
        token_ok = (sodium_memcmp(provided_hash, stored_hash, AUTH_TOKEN_BYTES) == 0);
    }
    
    sodium_memzero(provided_token, sizeof(provided_token));
    sodium_memzero(provided_hash, sizeof(provided_hash));
    sodium_memzero(token_hex, sizeof(token_hex));
    sodium_memzero(stored_hash, sizeof(stored_hash));   

    if (!token_ok) {
        write_message("{\"error\":\"invalid auth token\"}");
        sodium_memzero(master, sizeof(master));
        return 0;
    }

    int ok = validate_with_password(master, key, salt, nonce);
    sodium_memzero(master, sizeof(master));

    if (!ok) {
        write_message("{\"error\":\"invalid master password\"}");
        sodium_memzero(key, sizeof(key));
        return 0;
    }

    write_message("{\"status\":\"unlocked\"}");

    while (1) {
        char* req = NULL;
        if (!read_message(&req)) break;

        char req_action[32] = {0};
        char url[512] = {0};

        json_extract(req, "action", req_action, sizeof(req_action));
        json_extract(req, "url", url, sizeof(url));
        free(req);


        if (strcmp(req_action, "get_credentials") != 0) {
            write_message("{\"error\":\"unknown action\"}");
            continue;
        }

        char domain[512] = {0};
        domain_extract(url, domain, sizeof(domain));

        char user[512] = {0};
        char pass[512] = {0};
        
        int res = get_credential(domain, user, pass, key);
        if (res != 1) {
            if (res == -1) {
                write_message("{\"error\":\"database error\"}");
            } else {
                write_message("{\"error\":\"domain not found in the database\"}");
            }
            continue;
        }

        char user_esc[1024] = {0};
        char pass_esc[1024] = {0};

        if (json_escape(user, user_esc, sizeof(user_esc)) < 0 || 
            json_escape(pass, pass_esc, sizeof(pass_esc)) < 0) {
            write_message("{\"error\":\"internal error\"}");
            sodium_memzero(user, sizeof(user));
            sodium_memzero(pass, sizeof(pass));
            sodium_memzero(user_esc, sizeof(user_esc));
            sodium_memzero(pass_esc, sizeof(pass_esc));
            continue;
        }

        char response[sizeof(user_esc) + sizeof(pass_esc) + 64];
        snprintf(response, sizeof(response),
            "{\"username\":\"%s\",\"password\":\"%s\"}", user_esc, pass_esc);

        write_message(response);

        sodium_memzero(user, sizeof(user));
        sodium_memzero(pass, sizeof(pass));
        sodium_memzero(user_esc, sizeof(user_esc));
        sodium_memzero(pass_esc, sizeof(pass_esc));
        sodium_memzero(response, sizeof(response));
    }

    sodium_memzero(key, sizeof(key));
    return 1;

}