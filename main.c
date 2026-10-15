#include "backend.h"
#include <stdio.h>
#include <sqlite3.h>
#include <sodium.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#define MAXL 2048
#define MAX_CREDENTIALS 1024
static const unsigned char CHECK_MESSAGE[] = "vault-check";
#define MESSAGE_LEN (sizeof(CHECK_MESSAGE) -1)

typedef struct {
    int id;
    char site[MAXL];
    char username[MAXL];
    char password[MAXL];
} CredentialEntry;

CredentialEntry credential;


void manual(void) {
    puts(
        "\nPASSWORD MANAGER - CLI Usage:\n\n"
        "  ./pwmanager init          Create and initialize a new vault database\n"
        "  ./pwmanager add           Add new credentials to the vault\n"
        "  ./pwmanager get           List and copy credentials to clipboard\n"
        "  ./pwmanager del           Select and remove a credential\n"
        "  ./pwmanager gen <length>  Generate password (length between 16 and 128)\n"
        "  ./pwmanager native        Start Native Messaging host for browser extension\n"
        "  ./pwmanager newpw         Set a new master password\n"
    );
}

int input_secret(const char* label, char* bf, size_t bf_size) {
    printf("%s", label);
    if (fgets(bf, bf_size, stdin) == NULL) {
        sodium_memzero(bf, bf_size);
        return 0;
    }

    size_t len = strcspn(bf, "\n");

    if (bf[len] == '\n') {
        bf[len] = '\0';
    } else {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
        sodium_memzero(bf, bf_size);
        printf("\nError: input too long (limit of %zu characters).\n", bf_size - 1);
        return 0;
    }

    if (bf[0] == '\0') {
        sodium_memzero(bf, bf_size);
        return 0;
    }

    return 1;
}

int input_int(int* opt){
    char input[MAXL] = {0};
    char* end = NULL;
    long value;

    if (fgets(input, sizeof(input), stdin) == NULL) return 0;

    input[strcspn(input, "\n")] = '\0';

    errno = 0; // strtol reports overflow through errno

    value = strtol(input, &end, 10);

    if (errno != 0 || end == input || *end != '\0') {
        sodium_memzero(input, sizeof(input));
        return 0;
    }

    if (value < 1 || value > 2147483647) {
        sodium_memzero(input, sizeof(input));
        return 0;
    }

    *opt = (int)value;

    sodium_memzero(input, sizeof(input));
    return 1;
}

int hidden_field(char* bf) {
    struct termios old, new;

    if (tcgetattr(STDIN_FILENO, &old) != 0) return 0;
    
    new = old;
    new.c_lflag &= ~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &new) != 0) return 0;

    if (fgets(bf, MAXL, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        return 0;
    }


    tcsetattr(STDIN_FILENO, TCSANOW, &old);

    bf[strcspn(bf, "\n")] = '\0';



    return 1;
}

int create_db() {
    sqlite3 *db;
    int rc = sqlite3_open(VAULT_PATH, &db);

    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    const char *sql_credentails =
        "CREATE TABLE IF NOT EXISTS credentials ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "nonce BLOB NOT NULL,"
        "ciphertext BLOB NOT NULL"
        ");";

    const char* sql_vault = 
        "CREATE TABLE IF NOT EXISTS vault ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "salt BLOB NOT NULL,"
        "kdf_alg TEXT NOT NULL,"
        "opslimit INTEGER NOT NULL,"
        "memlimit INTEGER NOT NULL,"
        "check_nonce BLOB NOT NULL,"
        "check_ciphertext BLOB NOT NULL,"
        "auth_token BLOB NOT NULL"
        ");";
        

    rc = sqlite3_exec(db, sql_credentails, 0, 0, 0);    
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_exec(db, sql_vault, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    sqlite3_close(db);

    return 1;
}

int save_vault(unsigned char* salt, unsigned char* check_nonce, unsigned char* check_ciphertext, unsigned char* auth_token) {
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_open(VAULT_PATH, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    const char* sql = "INSERT OR REPLACE INTO vault "
    "(id, salt, kdf_alg, opslimit, memlimit, check_nonce, check_ciphertext, auth_token) "
    "VALUES (1, ?,?,?,?,?,?,?);";

    rc = sqlite3_prepare_v2(db, sql, -1 , &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_blob(stmt, 1, salt, crypto_pwhash_SALTBYTES, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "crypto_pwhash_ALG_DEFAULT", -1,SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, crypto_pwhash_OPSLIMIT_SENSITIVE);
    sqlite3_bind_int64(stmt, 4, crypto_pwhash_MEMLIMIT_SENSITIVE);
    sqlite3_bind_blob(stmt, 5, check_nonce, crypto_secretbox_NONCEBYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, check_ciphertext, crypto_secretbox_MACBYTES + MESSAGE_LEN, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 7, auth_token, AUTH_TOKEN_BYTES, SQLITE_STATIC);
    

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return rc == SQLITE_DONE;
}

int init(unsigned char* key, unsigned char* salt, unsigned char* check_nonce) {

    char master[MAXL] = {0};
    char confirm[MAXL] = {0};

    while (1) {
        printf("Master Password: ");
        if (hidden_field(master) != 1) {
            sodium_memzero(master, sizeof(master));
            sodium_memzero(confirm, sizeof(confirm));
            return 0;
        }

        printf("\nConfirm Master Password: ");
        if (hidden_field(confirm) != 1) {
            sodium_memzero(master, sizeof(master));
            sodium_memzero(confirm, sizeof(confirm));
            return 0;
        }

        if (sodium_memcmp(master, confirm, MAXL) != 0) {
            printf("\n\nPassword does not match. Try again.\n");
            sodium_memzero(master, sizeof(master));
            sodium_memzero(confirm, sizeof(confirm));
            continue;

        } else {
            if(!create_db()) return 0;
            break;
        }

    }

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
 
    // The SENSITIVE limits make each guess costly in CPU and RAM, which blunts GPU brute-force.
    if (crypto_pwhash( 
        key, crypto_secretbox_KEYBYTES,
        master, strlen(master),
        salt,
        crypto_pwhash_OPSLIMIT_SENSITIVE,
        crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) {
        sodium_memzero(master, sizeof(master));
        sodium_memzero(confirm, sizeof(confirm));
        return 0;
    }

    sodium_memzero(master, sizeof(master));
    sodium_memzero(confirm, sizeof(confirm));

    // Known message encrypted with the derived key. At login, a correct master password
    // re-derives the same key and decrypts it, so the password is verified without being stored.
    unsigned char check_ciphertext[crypto_secretbox_MACBYTES + MESSAGE_LEN];
    randombytes_buf(check_nonce, crypto_secretbox_NONCEBYTES);

    crypto_secretbox_easy(
        check_ciphertext,
        CHECK_MESSAGE,
        sizeof(CHECK_MESSAGE) -1,
        check_nonce,
        key
    );

    unsigned char auth_token[AUTH_TOKEN_BYTES];
    randombytes_buf(auth_token, sizeof(auth_token));

    // Only a hash of the token is persisted — the native host only ever needs
    // to VERIFY the token the extension sends, never read it back.
    unsigned char auth_token_hash[AUTH_TOKEN_BYTES];
    crypto_generichash(auth_token_hash, sizeof(auth_token_hash), auth_token, sizeof(auth_token), NULL, 0);

    if (!save_vault(salt, check_nonce, check_ciphertext, auth_token_hash)) {
        sodium_memzero(key, crypto_secretbox_KEYBYTES);
        sodium_memzero(auth_token, sizeof(auth_token));
        sodium_memzero(auth_token_hash, sizeof(auth_token_hash));
        return 0;
    }

    char token_hex[AUTH_TOKEN_BYTES *2 +1];
    sodium_bin2hex(token_hex, sizeof(token_hex), auth_token, sizeof(auth_token));

    printf("\n\n=== EXTENSION AUTHENTICATION TOKEN ===\n");
    printf("%s\n", token_hex);
    printf("Copy this token and paste it into the extension's options.\n");
    printf("It will not be shown again.\n");
    printf("==========================================\n\n");
    
    sodium_memzero(auth_token, sizeof(auth_token));
    sodium_memzero(token_hex, sizeof(token_hex));
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_memzero(auth_token_hash, sizeof(auth_token_hash));
    return 1;
}

static int load_vault(unsigned char* salt, long long* opslimit, long long* memlimit,
    unsigned char* nonce, unsigned char* ciphertext) {
    
    sqlite3 *db;
    sqlite3_stmt *stmt;

    int rc = sqlite3_open(VAULT_PATH, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    const char *sql =
        "SELECT salt, opslimit, memlimit, check_nonce, check_ciphertext "
        "FROM vault WHERE id = 1;"; 


    rc = sqlite3_prepare_v2(db, sql, -1 , &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    if (
        sqlite3_column_bytes(stmt, 0) != crypto_pwhash_SALTBYTES ||
        sqlite3_column_bytes(stmt, 3) != crypto_secretbox_NONCEBYTES ||
        sqlite3_column_bytes(stmt, 4) != (int) (crypto_secretbox_MACBYTES + MESSAGE_LEN)
    ) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    memcpy(salt, sqlite3_column_blob(stmt, 0), crypto_pwhash_SALTBYTES);
    *opslimit = sqlite3_column_int64(stmt, 1);
    *memlimit = sqlite3_column_int64(stmt, 2);
    memcpy(nonce, sqlite3_column_blob(stmt, 3), crypto_secretbox_NONCEBYTES);
    memcpy(ciphertext, sqlite3_column_blob(stmt, 4), crypto_secretbox_MACBYTES + MESSAGE_LEN);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 1;
}

static int derive_and_check(const char* master, unsigned char* key, const unsigned char* salt,
    long long opslimit, long long memlimit, const unsigned char* nonce, const unsigned char* ciphertext) {
    
    if (crypto_pwhash(
        key, crypto_secretbox_KEYBYTES,
        master, strlen(master),
        salt,
        opslimit,
        memlimit,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) {
        sodium_memzero(key, crypto_secretbox_KEYBYTES);
        return 0;
    }

    // Decryption only succeeds if the derived key is correct.
    unsigned char decrypted[MESSAGE_LEN];
    int valid = 0;
   
    if (crypto_secretbox_open_easy(
        decrypted, 
        ciphertext,
        crypto_secretbox_MACBYTES + MESSAGE_LEN,
        nonce,
        key
    ) == 0 && sodium_memcmp(decrypted, CHECK_MESSAGE, MESSAGE_LEN) == 0) {
        valid = 1;
    }

    sodium_memzero(decrypted, sizeof(decrypted));

    if (!valid) sodium_memzero(key, crypto_secretbox_KEYBYTES);
    
    return valid;

}

int validate(unsigned char* key, unsigned char* salt, unsigned char* nonce) {
    long long opslimit, memlimit;
    unsigned char ciphertext[crypto_secretbox_MACBYTES + MESSAGE_LEN];

    if (!load_vault(salt, &opslimit, &memlimit, nonce, ciphertext)) return 0;

    char master[MAXL] = {0};

    printf("\nMaster Password: ");
    if (hidden_field(master) != 1) {
        sodium_memzero(master, sizeof(master));
        return 0;
    }
    printf("\n");

    int valid = derive_and_check(master, key, salt, opslimit, memlimit, nonce, ciphertext);
    sodium_memzero(master, sizeof(master));
    
    if (!valid) {
        printf("\nInvalid Master Password.\n");
        return 0;
    }
    
    return 1;    
}

int validate_with_password(const char* master, unsigned char* key, unsigned char* salt, unsigned char* nonce) {
    long long opslimit, memlimit;
    unsigned char ciphertext[crypto_secretbox_MACBYTES + MESSAGE_LEN];

    if (!load_vault(salt, &opslimit, &memlimit, nonce, ciphertext)) return 0;

    return derive_and_check(master, key, salt, opslimit, memlimit, nonce, ciphertext);
}

int load_token(unsigned char* token) {
    sqlite3* db;
    sqlite3_stmt *stmt;

    int rc = sqlite3_open(VAULT_PATH, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    const char* sql = "SELECT auth_token FROM vault WHERE id = 1;";

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW || sqlite3_column_bytes(stmt, 0) != AUTH_TOKEN_BYTES) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }


    memcpy(token, sqlite3_column_blob(stmt, 0), AUTH_TOKEN_BYTES);

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 1;
}

int save_credential(const unsigned char* nonce, const unsigned char* ciphertext, int ciphertext_len) {
    sqlite3 *db;
    sqlite3_stmt *stmt;

    int rc = sqlite3_open(VAULT_PATH, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    const char* sql =
    "INSERT INTO credentials (nonce, ciphertext) "
    "VALUES (?, ?);"; 

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_blob(stmt, 1, nonce, crypto_secretbox_NONCEBYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, ciphertext, ciphertext_len, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return rc == SQLITE_DONE;
}

int add_credential(const unsigned char* key) {
    char domain[MAXL] = {0};
    char site[MAXL] = {0};
    char username[MAXL] = {0};
    char password[MAXL] = {0};
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char plaintext[MAXL * 3] = {0};
    unsigned char ciphertext[crypto_secretbox_MACBYTES + sizeof(plaintext)] = {0};

    if (!input_secret("site: ", domain, sizeof(domain))) return 0;

    domain_extract(domain, site, sizeof(site));

    if (!input_secret("Identifier: ", username, sizeof(username))) {
        sodium_memzero(site, sizeof(site));
        return 0;
    }
    
    printf("Password: ");
    if (hidden_field(password) != 1) {
        printf("\n");
        sodium_memzero(site, sizeof(site));
        sodium_memzero(username, sizeof(username));
        sodium_memzero(password, sizeof(password));
        return 0;
    }
    printf("\n");

    // Serialized as key=value lines; list_credentials and the native host parse this format.
    int plaintext_len = snprintf(
        (char*) plaintext,
        sizeof(plaintext),
        "site=%s\nusername=%s\npassword=%s",
        site,
        username,
        password
    );

    if (plaintext_len < 0 || plaintext_len >= (int) sizeof(plaintext)) {
        sodium_memzero(site, sizeof(site));
        sodium_memzero(username, sizeof(username));
        sodium_memzero(password, sizeof(password));
        return 0;
    }

    randombytes_buf(nonce, sizeof(nonce));
    crypto_secretbox_easy( 
        ciphertext,
        plaintext,
        plaintext_len,
        nonce,
        key
    );

    int ok = save_credential(
        nonce,
        ciphertext,
        crypto_secretbox_MACBYTES + plaintext_len
    );


    sodium_memzero(site, sizeof(site));
    sodium_memzero(username, sizeof(username));
    sodium_memzero(password, sizeof(password));
    sodium_memzero(plaintext, sizeof(plaintext));
    sodium_memzero(ciphertext, sizeof(ciphertext));

    return ok;

}

int clipboard(char* bf) {

    if (system("command -v xclip >/dev/null 2>&1") != 0) return -1;

    FILE *fp = popen("xclip -selection clipboard", "w");
    if (!fp) return -1;

    fputs(bf, fp);
    if (pclose(fp) != 0) return -1;

    return 1;
}

int list_credentials(unsigned char *key) {
    sqlite3* db;
    sqlite3_stmt* stmt = NULL;
    int result = 0;
    
    CredentialEntry *entries = calloc(MAX_CREDENTIALS, sizeof(CredentialEntry));
    if (entries == NULL) {
        printf("\nError: failed to allocate memory.\n");
        return 0;
    }
    
    int count = 0;

    int rc = sqlite3_open(VAULT_PATH, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        goto cleanup;
    }

    const char *sql =
        "SELECT id, nonce, ciphertext "
        "FROM credentials "
        "ORDER BY id;";
        
    
        
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        goto cleanup;
    }

    
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && count < MAX_CREDENTIALS) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *nonce = sqlite3_column_blob(stmt, 1);
        const unsigned char *ciphertext = sqlite3_column_blob(stmt, 2);
    
        int nonce_len = sqlite3_column_bytes(stmt, 1);    
        int ciphertext_len = sqlite3_column_bytes(stmt, 2);

        if (nonce_len != crypto_secretbox_NONCEBYTES ||
        ciphertext_len <= crypto_secretbox_MACBYTES) continue;

        unsigned char plaintext[MAXL *3 + 1] = {0};
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

            entries[count].id = id;
            snprintf(entries[count].site, sizeof(entries[count].site), "%s", site);
            snprintf(entries[count].username, sizeof(entries[count].username), "%s", username);
            snprintf(entries[count].password, sizeof(entries[count].password), "%s", password);
            
            count++;
        } 
        
        sodium_memzero(plaintext, sizeof(plaintext));

    }
    

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (rc != SQLITE_DONE) goto cleanup;

    if (count == 0) {
        printf("\nNo sites found.\n");
        goto cleanup;
    }

    int opt = 0;

    while (1) {

        for (int i=0; i<count; i++) {
            printf("%d. %s\n", i+1, entries[i].site);
        }

        printf("Choose an option by number: ");
        if (!input_int(&opt) || opt > count) {
            printf("Invalid option.\n");
            continue;
        }

        credential.id  = entries[opt -1].id;
        strcpy(credential.site, entries[opt -1].site);
        strcpy(credential.username, entries[opt -1].username);
        strcpy(credential.password, entries[opt -1].password);

        break;
    } 

    result = 1;

cleanup:
    sodium_memzero(entries, MAX_CREDENTIALS * sizeof(CredentialEntry));
    free(entries);
    return result;

}

int get_credential(unsigned char *key) {
    
    if(!list_credentials(key)) return 0;

    printf("\nIdentifier: %s\n", credential.username);
    if (clipboard(credential.password) == -1) {
        printf("Password: %s\n", credential.password);
        printf("\nInstall xclip on your system so your password is copied automatically rather than displayed unnecessarily, thereby preventing shoulder surfing attacks.\n");
        sodium_memzero(&credential, sizeof(credential));
        return 1;
    }
    printf("\nCopied Password.\n");
    
    sodium_memzero(&credential, sizeof(credential));

    return 1;
}

int delete_credential(unsigned char* key) {

    if (!list_credentials(key)) {
        sodium_memzero(&credential, sizeof(credential));
        return 0;
    }

    sqlite3 *db;
    sqlite3_stmt *stmt;

    int rc = sqlite3_open(VAULT_PATH, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    const char *sql = "DELETE FROM credentials WHERE id = ?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_int(stmt, 1, credential.id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        printf("\nError removing credential.\n");
        sqlite3_close(db);
        sodium_memzero(&credential, sizeof(credential));
        return 0;
    }

    int deleted = sqlite3_changes(db);
    sqlite3_close(db);

    if (deleted == 0) {
        printf("\nID not found.\n");
    } else {
        printf("\nCredential removed successfully.\n");
    }

    sodium_memzero(&credential, sizeof(credential));

    return 1;
}

int generate_password(int length) {
    const char lower[] = "abcdefghijklmnopqrstuvwxyz";
    const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char digits[] = "0123456789";
    const char symbols[] = "!@#$%^&*()-_=+[]{};:,.<>?";
    const char all[] = 
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{};:,.<>?";


    char password[128 + 1] = {0};
    
    if (length < 16 || length > 128) return 0;

    password[0] = lower[randombytes_uniform(strlen(lower))];
    password[1] = upper[randombytes_uniform(strlen(upper))];
    password[2] = digits[randombytes_uniform(strlen(digits))];
    password[3] = symbols[randombytes_uniform(strlen(symbols))];

    for (int i=4; i<length; i++) {
        password[i] = all[randombytes_uniform(strlen(all))];
    }

    // Fisher-Yates shuffle, so the four guaranteed characters don't stay in fixed positions.
    for (int i = length-1; i>0; i--){
        int j = randombytes_uniform(i+1);
        char tmp = password[i];
        password[i] = password[j];
        password[j] = tmp;
    }

    if (clipboard(password) == -1) {
        printf("\nPassword: %s\n", password);
        printf("\nInstall xclip on your system so your password is copied automatically rather than displayed unnecessarily, thereby preventing shoulder surfing attacks.\n");
        sodium_memzero(password, sizeof(password));
        return 1;
    }

    printf("\nCopied Password.\n");
    sodium_memzero(password, sizeof(password));

    return 1;
}

int update_vault(unsigned char* salt, unsigned char* check_nonce, unsigned char* check_ciphertext, sqlite3 *db) {
    sqlite3_stmt *stmt = NULL;

    const char *sql = "UPDATE vault SET salt = ?, opslimit = ?, memlimit = ?, check_nonce = ?, check_ciphertext = ? WHERE id = 1;";

    int rc = sqlite3_prepare_v2(db, sql, -1 , &stmt, NULL);
    if (rc != SQLITE_OK) {
        return 0;
    }

    sqlite3_bind_blob(stmt, 1, salt, crypto_pwhash_SALTBYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, crypto_pwhash_OPSLIMIT_SENSITIVE);
    sqlite3_bind_int64(stmt, 3, crypto_pwhash_MEMLIMIT_SENSITIVE);
    sqlite3_bind_blob(stmt, 4, check_nonce, crypto_secretbox_NONCEBYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, check_ciphertext, crypto_secretbox_MACBYTES + MESSAGE_LEN, SQLITE_STATIC);
    

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

int update_credential(const unsigned char* nonce, const unsigned char* ciphertext, int ciphertext_len, int id, sqlite3 *db) {
    sqlite3_stmt *stmt = NULL;

    const char *sql = "UPDATE credentials SET nonce = ?, ciphertext = ? WHERE id = ?;"; 

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return 0;
    }

    sqlite3_bind_blob(stmt, 1, nonce, crypto_secretbox_NONCEBYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, ciphertext, ciphertext_len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

int change_password(unsigned char *key, unsigned char* salt, unsigned char* new_nonce) {
    char master[MAXL] = {0};
    char confirm[MAXL] = {0};

    while (1) {
        printf("New Master Password: ");
        if (hidden_field(master) != 1) {
            goto cleanpwd;
        }

        printf("\nConfirm Master Password: ");
        if (hidden_field(confirm) != 1) {
            goto cleanpwd;
        }

        if (sodium_memcmp(master, confirm, MAXL) != 0) {
            printf("\n\nPassword does not match. Try again.\n");
            sodium_memzero(master, sizeof(master));
            sodium_memzero(confirm, sizeof(confirm));
            continue;

        } else {
            if(!create_db()) goto cleanpwd;
            break;
        }

    }

    sqlite3* db;
    sqlite3_stmt* stmt = NULL;
    int result = 0;
    CredentialEntry *entries = NULL;

    unsigned char new_key[crypto_secretbox_KEYBYTES];
    unsigned char new_ciphertext[crypto_secretbox_MACBYTES + MESSAGE_LEN];

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);

    if (crypto_pwhash(
        new_key, crypto_secretbox_KEYBYTES,
        master, strlen(master),
        salt,
        crypto_pwhash_OPSLIMIT_SENSITIVE,
        crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) {
        goto cleanpwd;
    }

    sodium_memzero(master, sizeof(master));
    sodium_memzero(confirm, sizeof(confirm));

    randombytes_buf(new_nonce, crypto_secretbox_NONCEBYTES);

    crypto_secretbox_easy(
        new_ciphertext,
        CHECK_MESSAGE,
        sizeof(CHECK_MESSAGE) -1,
        new_nonce, 
        new_key 
    );

    int rc = sqlite3_open(VAULT_PATH, &db);
    if (rc != SQLITE_OK) goto cleanup;
    
    entries = calloc(MAX_CREDENTIALS, sizeof(CredentialEntry));
    if (entries == NULL) {
        printf("\nError: failed to allocate memory.\n");
        goto cleanup;
    }

    int count = 0;
    int skipped = 0;

    const char *sql =
        "SELECT id, nonce, ciphertext "
        "FROM credentials "
        "ORDER BY id;";
        
        
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        goto cleanup;
    }

    
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && count < MAX_CREDENTIALS) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *nonce = sqlite3_column_blob(stmt, 1);
        const unsigned char *ciphertext = sqlite3_column_blob(stmt, 2);
    
        int nonce_len = sqlite3_column_bytes(stmt, 1);    
        int ciphertext_len = sqlite3_column_bytes(stmt, 2);

        if (nonce_len != crypto_secretbox_NONCEBYTES ||
        ciphertext_len <= crypto_secretbox_MACBYTES) {skipped++; continue;}

        unsigned char plaintext[MAXL *3 + 1] = {0};
        int plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES;

        if (plaintext_len >= (int) sizeof(plaintext)) {skipped++; continue;}

        if (crypto_secretbox_open_easy(
            plaintext,
            ciphertext,
            ciphertext_len,
            nonce,
            key
        ) != 0) {
            sodium_memzero(plaintext, sizeof(plaintext));
            skipped++;
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

            entries[count].id = id;
            snprintf(entries[count].site, sizeof(entries[count].site), "%s", site);
            snprintf(entries[count].username, sizeof(entries[count].username), "%s", username);
            snprintf(entries[count].password, sizeof(entries[count].password), "%s", password);
            
            count++;

        } else skipped++;
        
        sodium_memzero(plaintext, sizeof(plaintext));
    }

    sqlite3_finalize(stmt);
    stmt = NULL;

    if (rc != SQLITE_DONE) {
        printf("\nCould not read every record (database error or more than %d records). "
            "Password change aborted; vault unchanged.\n", MAX_CREDENTIALS);
        goto cleanup;
    }

    if (skipped > 0) {
        printf("\n%d record(s) could not be read or decrypted. "
            "Password change aborted; vault unchanged.\n", skipped);
        goto cleanup;
    }

    if (sqlite3_exec(db, "BEGIN TRANSACTION;", 0, 0, 0) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
        printf("\nFailed to begin transaction. Password change aborted; vault unchanged.\n");
        goto cleanup;
    }

    if (!update_vault(salt, new_nonce, new_ciphertext, db)) {
        sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
        printf("\nFailed to update vault. Password change aborted.\n");
        goto cleanup;
    }
        
    unsigned char plaintext2[MAXL *3] = {0};       
    unsigned char ciphertext2[crypto_secretbox_MACBYTES + sizeof(plaintext2)] = {0};

    int ok = 1;
    for (int i=0; i<count; i++) {
        int plaintext_len = snprintf(
            (char*) plaintext2,
            sizeof(plaintext2),
            "site=%s\nusername=%s\npassword=%s",
            entries[i].site,
            entries[i].username,
            entries[i].password
        );

        if (plaintext_len < 0 || plaintext_len >= (int) sizeof(plaintext2)) {
            ok = 0;
            break;
        }

        randombytes_buf(new_nonce, crypto_secretbox_NONCEBYTES);
        crypto_secretbox_easy( 
            ciphertext2, 
            plaintext2,  
            plaintext_len,
            new_nonce,
            new_key
        );

        if (!update_credential(
            new_nonce,
            ciphertext2,
            crypto_secretbox_MACBYTES + plaintext_len,
            entries[i].id,
            db
        )) {
            ok = 0;
            break;
        }
    }

    sodium_memzero(plaintext2, sizeof(plaintext2));
    sodium_memzero(ciphertext2, sizeof(ciphertext2));

    if (!ok) {
        sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
        printf("\nFailed to update a credential. Password change aborted; vault unchanged.\n");
        goto cleanup;
    }

    if (sqlite3_exec(db, "COMMIT;", 0, 0, 0) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
        printf("\nFailed to commit. Password change aborted; vault unchanged.\n");
        goto cleanup;
    }

    printf("\nNew password successfully updated.\n");

    result = 1;


cleanup:
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    if (entries) {
        sodium_memzero(entries, MAX_CREDENTIALS * sizeof(CredentialEntry));
        free(entries);
    }

    sodium_memzero(master, sizeof(master));
    sodium_memzero(confirm, sizeof(confirm));
    sodium_memzero(new_key, sizeof(new_key)); 
    return result; 
     
cleanpwd:
    sodium_memzero(master, sizeof(master));
    sodium_memzero(confirm, sizeof(confirm));
    sodium_memzero(new_key, sizeof(new_key));
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        manual();
        return 0;
    }

    if (sodium_init() < 0) {
        printf("libsodium error.\n");
        return 1;
    }

    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    if (strcmp(argv[1], "init") == 0) {
        FILE *f = fopen(VAULT_PATH, "r");
        if (f != NULL) {
            fclose(f);
            printf("\nvault.db already exists; refusing to overwrite\n");
            return 1;
        }
        init(key, salt, nonce);
        

    } else if (strcmp(argv[1], "add") == 0){
        if (validate(key, salt, nonce) == 1) {
            add_credential(key);
        } else return 1;

    } else if (strcmp(argv[1], "del") == 0) {
        if (validate(key, salt, nonce) == 1) {
            delete_credential(key);
        } else return 1;
    
    } else if (strcmp(argv[1], "newpw") == 0) {
        if (validate(key,salt, nonce) == 1) {
            change_password(key, salt, nonce);
        } else return 1;

    } else if (strcmp(argv[1], "get") == 0) {
        if (validate(key, salt, nonce) == 1) {
            get_credential(key);
        } else return 1;
    
    } else if (strcmp(argv[1], "native") == 0) {
        native_server();

    } else if (strcmp(argv[1], "gen") == 0) {
        if (argc == 3) {
            char* entered = argv[2];
            char* end = NULL;
            long value;
           
            errno = 0;
            value = strtol(entered, &end, 10);

            if (errno != 0 || end == entered || *end != '\0') {
                printf("\nThis is not a number.\n");
                return 1;
            }

            if (value < 16 || value > 128) {
                printf("\nInvalid number. Use 16 to 128.\n");
                return 1;
            }

            generate_password((int)value);

        } else {
            printf("\nUsage: ./pwmanager ger <length>\n");
            return 1;
        }
        
    }

    return 0;
}