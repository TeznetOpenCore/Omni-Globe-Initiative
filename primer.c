// prime_chain.c
// Sequential hash chain with OpenSSL EVP API (OpenSSL 3.0+ safe)

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP_MS(ms) Sleep((DWORD)(ms))
#else
#include <unistd.h>
static void SLEEP_MS(double ms) {
    if (ms <= 0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000.0);
    ts.tv_nsec = (long)((ms - ts.tv_sec * 1000.0) * 1e6 * 1000.0);
    nanosleep(&ts, NULL);
}
#endif

#include <openssl/evp.h>

// ===============================
// Chain state structure
// ===============================
typedef struct {
    int use_hex_seed;          // 0 = ascii seed, 1 = hex seed
    unsigned char *seed;       // seed bytes
    size_t seed_len;
    unsigned char hash[32];    // current hash (Hi)
    unsigned long long index;  // i for Hi (H0 after first hash of seed)
} chain_state;

// ===============================
// Hex helpers
// ===============================
static int hexval(char c) {
    if ('0'<=c && c<='9') return c-'0';
    if ('a'<=c && c<='f') return c-'a'+10;
    if ('A'<=c && c<='F') return c-'A'+10;
    return -1;
}

static int from_hex(const char *hex, unsigned char **out, size_t *outlen) {
    size_t n = strlen(hex);
    if (n % 2) return -1;
    *outlen = n/2;
    *out = (unsigned char*)malloc(*outlen);
    if (!*out) return -1;
    for (size_t i=0; i<*outlen; i++) {
        int hi = hexval(hex[2*i]);
        int lo = hexval(hex[2*i+1]);
        if (hi<0||lo<0){ free(*out); return -1; }
        (*out)[i] = (unsigned char)((hi<<4)|lo);
    }
    return 0;
}

static void to_hex(const unsigned char *in, size_t n, char *out) {
    static const char *digits="0123456789abcdef";
    for (size_t i=0; i<n; i++) {
        out[2*i]   = digits[(in[i]>>4)&0xF];
        out[2*i+1] = digits[in[i]&0xF];
    }
    out[2*n] = '\0';
}

// ===============================
// SHA256 wrapper (EVP API)
// ===============================
static void sha256_bytes(const unsigned char *in, size_t len, unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fprintf(stderr,"EVP_MD_CTX_new failed\n"); exit(1); }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr,"EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }

    if (EVP_DigestUpdate(ctx, in, len) != 1) {
        fprintf(stderr,"EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }

    unsigned int outlen = 0;
    if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1 || outlen != 32) {
        fprintf(stderr,"EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }

    EVP_MD_CTX_free(ctx);
}

// ===============================
// Timestamp helper
// ===============================
static void iso_timestamp(char *buf, size_t n){
    time_t t=time(NULL);
    struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    strftime(buf, n, "%Y-%m-%dT%H:%M:%S%z", &tm);
}

// ===============================
// MAIN
// ===============================
int main(int argc, char **argv) {
    const char *seed_ascii = NULL;
    unsigned long long steps = 10;
    double hps = 1.0;

    // simple args: ./prime_chain [seed-string]
    if (argc > 1) {
        seed_ascii = argv[1];
    } else {
        seed_ascii = "2^82589933-1";
    }

    chain_state st = {0};
    st.use_hex_seed = 0;
    st.seed_len = strlen(seed_ascii);
    st.seed = (unsigned char*)malloc(st.seed_len);
    memcpy(st.seed, seed_ascii, st.seed_len);

    // Start chain: H0 = SHA256(seed)
    sha256_bytes(st.seed, st.seed_len, st.hash);
    st.index = 0ULL;

    char h[65]; 
    to_hex(st.hash, 32, h);
    char ts[40]; 
    iso_timestamp(ts, sizeof ts);
    printf("%s i=%llu H=%s (genesis)\n", ts, st.index, h);

    // Main loop
    for (unsigned long long done = 0; done < steps; done++) {
        unsigned char next[32];
        sha256_bytes(st.hash, 32, next);
        memcpy(st.hash, next, 32);
        st.index++;

        to_hex(st.hash, 32, h);
        iso_timestamp(ts, sizeof ts);
        printf("%s i=%llu H=%s\n", ts, st.index, h);

        if (hps > 0.0) SLEEP_MS(1000.0/hps);
    }

    free(st.seed);
    return 0;
}

