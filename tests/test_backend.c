/*
 * Unit tests for the parsing helpers in backend.c.
 *
 * backend.c is included directly (instead of linked) so the tests can reach
 * its static helpers: json_extract() and json_escape().
 */
#include "../backend.c"

/*
 * backend.c calls two functions that live in main.c (which has its own main()).
 * They are not exercised by these tests, so simple stubs satisfy the linker.
 */
int load_token(unsigned char* token) { (void) token; return 0; }
int validate_with_password(const char* master, unsigned char* key,
    unsigned char* salt, unsigned char* nonce) {
    (void) master; (void) key; (void) salt; (void) nonce;
    return 0;
}

static int failures = 0;
static int checks = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        checks++;                                                        \
        if (!(cond)) {                                                   \
            failures++;                                                  \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        }                                                                \
    } while (0)

#define CHECK_STR(actual, expected) CHECK(strcmp((actual), (expected)) == 0)

/* ---------- domain_extract ---------- */

static void test_domain_extract(void) {
    char out[64];

    domain_extract("https://example.com/login", out, sizeof(out));
    CHECK_STR(out, "example.com");

    domain_extract("http://localhost:3000/login.html", out, sizeof(out));
    CHECK_STR(out, "localhost");

    domain_extract("example.com/path", out, sizeof(out));
    CHECK_STR(out, "example.com");

    domain_extract("https://sub.example.com?x=1", out, sizeof(out));
    CHECK_STR(out, "sub.example.com");

    domain_extract("https://example.com#section", out, sizeof(out));
    CHECK_STR(out, "example.com");

    /* output is truncated and always NUL-terminated */
    char small[8];
    domain_extract("https://averyveryverylongdomain.com", small, sizeof(small));
    CHECK(strlen(small) == 7);
}

/* ---------- json_extract ---------- */

static void test_json_extract(void) {
    char out[64];

    CHECK(json_extract("{\"action\":\"unlock\"}", "action", out, sizeof(out)) == 1);
    CHECK_STR(out, "unlock");

    CHECK(json_extract("{\"a\":\"1\",\"b\":\"2\"}", "b", out, sizeof(out)) == 1);
    CHECK_STR(out, "2");

    /* whitespace around the colon */
    CHECK(json_extract("{ \"k\" :  \"v\" }", "k", out, sizeof(out)) == 1);
    CHECK_STR(out, "v");

    /* escape sequences */
    CHECK(json_extract("{\"p\":\"a\\\"b\\\\c\\nd\\te\"}", "p", out, sizeof(out)) == 1);
    CHECK_STR(out, "a\"b\\c\nd\te");

    /* \u escapes in the ASCII range are decoded */
    CHECK(json_extract("{\"p\":\"\\u0041\\u0062\"}", "p", out, sizeof(out)) == 1);
    CHECK_STR(out, "Ab");

    /* raw UTF-8 passes through untouched */
    CHECK(json_extract("{\"p\":\"caf\xc3\xa9\"}", "p", out, sizeof(out)) == 1);
    CHECK_STR(out, "caf\xc3\xa9");

    /* documented limitation: \u escapes above 0x7F are rejected */
    CHECK(json_extract("{\"p\":\"\\u00e9\"}", "p", out, sizeof(out)) == 0);

    /* missing key */
    CHECK(json_extract("{\"a\":\"1\"}", "nope", out, sizeof(out)) == 0);

    /* unterminated string */
    CHECK(json_extract("{\"a\":\"abc", "a", out, sizeof(out)) == 0);

    /* invalid escape and truncated \u */
    CHECK(json_extract("{\"a\":\"\\q\"}", "a", out, sizeof(out)) == 0);
    CHECK(json_extract("{\"a\":\"\\u00\"}", "a", out, sizeof(out)) == 0);

    /* trailing backslash at end of input */
    CHECK(json_extract("{\"a\":\"x\\", "a", out, sizeof(out)) == 0);

    /* value that does not fit the buffer is rejected, never overflowed */
    char tiny[4];
    CHECK(json_extract("{\"a\":\"abcdef\"}", "a", tiny, sizeof(tiny)) == 0);
    CHECK(json_extract("{\"a\":\"abc\"}", "a", tiny, sizeof(tiny)) == 1);
    CHECK_STR(tiny, "abc");
}

/* ---------- json_escape ---------- */

static void test_json_escape(void) {
    char out[64];

    CHECK(json_escape("plain", out, sizeof(out)) == 5);
    CHECK_STR(out, "plain");

    CHECK(json_escape("a\"b\\c", out, sizeof(out)) > 0);
    CHECK_STR(out, "a\\\"b\\\\c");

    CHECK(json_escape("l1\nl2\t", out, sizeof(out)) > 0);
    CHECK_STR(out, "l1\\nl2\\t");

    /* other control characters become \u00XX */
    CHECK(json_escape("\x01", out, sizeof(out)) == 6);
    CHECK_STR(out, "\\u0001");

    /* empty input */
    CHECK(json_escape("", out, sizeof(out)) == 0);
    CHECK_STR(out, "");

    /* output buffer too small */
    char tiny[4];
    CHECK(json_escape("abcd", tiny, sizeof(tiny)) == -1);
    CHECK(json_escape("abc", tiny, sizeof(tiny)) == 3);
}

/* ---------- escape -> extract round trip ---------- */

static void test_round_trip(void) {
    const char* secrets[] = {
        "simple",
        "with \"quotes\" and \\backslashes\\",
        "tab\there\nnewline",
        "p@ss/w0rd:with?symbols#and spaces",
        "caf\xc3\xa9 \xe2\x9c\x93",
    };

    for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); i++) {
        char esc[256], json[300], back[128];
        CHECK(json_escape(secrets[i], esc, sizeof(esc)) >= 0);
        snprintf(json, sizeof(json), "{\"password\":\"%s\"}", esc);
        CHECK(json_extract(json, "password", back, sizeof(back)) == 1);
        CHECK_STR(back, secrets[i]);
    }
}

int main(void) {
    test_domain_extract();
    test_json_extract();
    test_json_escape();
    test_round_trip();

    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
