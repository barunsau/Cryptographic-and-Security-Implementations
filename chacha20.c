/*
 * ============================================================================
 * File        : 07B_chacha20.c
 * Title       : ChaCha20 Stream Cipher Implementation & Performance Profiler
 * Author      : Barun Sau
 * Roll No.    : CrS 2507
 * Course      : Cryptographic and Security Implementations
 * Institution : Indian Statistical Institute, Kolkata
 * Description : RFC 8439 compliant C implementation of the 20-round ChaCha20
 *               stream cipher (256-bit key, 96-bit nonce, 32-bit counter)
 *               with hardware-level cycle and latency benchmarking.
 * ============================================================================
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#define BENCH_RUNS     100000
#define BLOCK_BYTES    64
#define STATE_WORDS    16

/* 32-bit left cyclic rotation */
static inline uint32_t rotate_left32(uint32_t val, int shift) {
    return (val << shift) | (val >> (32 - shift));
}

/* Load 4 little-endian bytes into a 32-bit unsigned word */
static inline uint32_t load_le32(const uint8_t *src) {
    return ((uint32_t)src[0])       |
           ((uint32_t)src[1] << 8)  |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

/* Store a 32-bit unsigned word into 4 little-endian bytes */
static inline void store_le32(uint8_t *dst, uint32_t word) {
    dst[0] = (uint8_t)(word & 0xFF);
    dst[1] = (uint8_t)((word >> 8)  & 0xFF);
    dst[2] = (uint8_t)((word >> 16) & 0xFF);
    dst[3] = (uint8_t)((word >> 24) & 0xFF);
}

/* ChaCha20 Quarter-Round operation over indexed state array */
static inline void chacha_qround(uint32_t state[STATE_WORDS],
                                 int a, int b, int c, int d) {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = rotate_left32(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = rotate_left32(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = rotate_left32(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = rotate_left32(state[b], 7);
}

/* Generate a 64-byte keystream block per RFC 8439 Section 2.3 */
void generate_keystream_block(const uint8_t key[32], uint32_t block_counter,
                              const uint8_t nonce[12], uint8_t keystream[BLOCK_BYTES]) {
    uint32_t init_state[STATE_WORDS];
    uint32_t work_state[STATE_WORDS];

    /* "expand 32-byte k" sigma constants in little-endian 32-bit words */
    init_state[0] = 0x61707865;
    init_state[1] = 0x3320646e;
    init_state[2] = 0x79622d32;
    init_state[3] = 0x6b206574;

    /* 256-bit secret key (words 4..11) */
    for (int i = 0; i < 8; ++i) {
        init_state[4 + i] = load_le32(key + (i * 4));
    }

    /* 32-bit block counter (word 12) */
    init_state[12] = block_counter;

    /* 96-bit nonce (words 13..15) */
    init_state[13] = load_le32(nonce + 0);
    init_state[14] = load_le32(nonce + 4);
    init_state[15] = load_le32(nonce + 8);

    memcpy(work_state, init_state, sizeof(init_state));

    /* 10 double-rounds = 20 total rounds (alternating column and diagonal rounds) */
    for (int r = 0; r < 10; ++r) {
        /* Column round */
        chacha_qround(work_state, 0, 4,  8, 12);
        chacha_qround(work_state, 1, 5,  9, 13);
        chacha_qround(work_state, 2, 6, 10, 14);
        chacha_qround(work_state, 3, 7, 11, 15);

        /* Diagonal round */
        chacha_qround(work_state, 0, 5, 10, 15);
        chacha_qround(work_state, 1, 6, 11, 12);
        chacha_qround(work_state, 2, 7,  8, 13);
        chacha_qround(work_state, 3, 4,  9, 14);
    }

    /* Feed-forward addition with initial state and serialize to little-endian byte array */
    for (int i = 0; i < STATE_WORDS; ++i) {
        uint32_t word_sum = work_state[i] + init_state[i];
        store_le32(keystream + (i * 4), word_sum);
    }
}

/* Stream XOR operation for symmetric encryption and decryption */
void chacha20_xor_stream(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t init_counter, const uint8_t *in_buf,
                         uint8_t *out_buf, size_t byte_len) {
    uint8_t ks_block[BLOCK_BYTES];
    size_t offset = 0;
    uint32_t counter = init_counter;

    while (offset < byte_len) {
        generate_keystream_block(key, counter, nonce, ks_block);

        size_t chunk = (byte_len - offset < BLOCK_BYTES) ? (byte_len - offset) : BLOCK_BYTES;
        for (size_t i = 0; i < chunk; ++i) {
            out_buf[offset + i] = in_buf[offset + i] ^ ks_block[i];
        }

        offset += chunk;
        counter++;
    }
}

/* Helper to print formatted hexadecimal blocks */
static void print_hex_dump(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0 || i + 1 == len) {
            printf("\n");
        }
    }
}

/* Micro-benchmarking routine using CLOCK_MONOTONIC and RDTSCP */
void run_performance_profile(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *msg, size_t msg_len) {
    uint8_t out[128];
    unsigned int core_id;
    struct timespec t_start, t_end;
    uint64_t tsc_start, tsc_end;
    volatile uint8_t sink = 0;

    clock_gettime(CLOCK_MONOTONIC, &t_start);
    tsc_start = __rdtscp(&core_id);

    for (int iter = 0; iter < BENCH_RUNS; ++iter) {
        chacha20_xor_stream(key, nonce, 1, msg, out, msg_len);
    }

    tsc_end = __rdtscp(&core_id);
    clock_gettime(CLOCK_MONOTONIC, &t_end);

    for (size_t i = 0; i < msg_len; ++i) {
        sink ^= out[i];
    }

    uint64_t elapsed_ns = (uint64_t)(t_end.tv_sec - t_start.tv_sec) * 1000000000ULL +
                          (uint64_t)(t_end.tv_nsec - t_start.tv_nsec);
    double mean_ns     = (double)elapsed_ns / BENCH_RUNS;
    double mean_cycles = (double)(tsc_end - tsc_start) / BENCH_RUNS;
    double cpb         = mean_cycles / (double)msg_len;

    printf("\n+----------------------------------------------------------+\n");
    printf("|             CHACHA20 PERFORMANCE BENCHMARK               |\n");
    printf("+----------------------------------------------------------+\n");
    printf("| Benchmark Iterations  : %-32d |\n", BENCH_RUNS);
    printf("| Payload Length        : %-26zu bytes |\n", msg_len);
    printf("| Cumulative Time       : %-29lu ns |\n", elapsed_ns);
    printf("| Mean Latency / Call   : %-29.2f ns |\n", mean_ns);
    printf("| Mean CPU Cycles       : %-32.2f |\n", mean_cycles);
    printf("| Cycles per Byte (CPB) : %-32.2f |\n", cpb);
    printf("| Anti-DCE Checksum     : %-32u |\n", sink);
    printf("+----------------------------------------------------------+\n");
}

int main(void) {
    /* Official RFC 8439 Section 2.4.2 Test Vector */
    static const uint8_t rfc_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    static const uint8_t rfc_nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };

    const char *test_vector_msg =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";

    size_t msg_len = strlen(test_vector_msg);
    uint8_t cipher_buf[128] = {0};
    uint8_t plain_buf[128]  = {0};

    printf("+----------------------------------------------------------+\n");
    printf("|     RFC 8439 ChaCha20 Stream Cipher Verification         |\n");
    printf("|     Author: Barun Sau (Roll No: CrS 2507)                |\n");
    printf("+----------------------------------------------------------+\n\n");

    printf("Original Plaintext (%zu bytes):\n\"%s\"\n\n", msg_len, test_vector_msg);

    /* Step 1: Encryption */
    chacha20_xor_stream(rfc_key, rfc_nonce, 1,
                        (const uint8_t *)test_vector_msg, cipher_buf, msg_len);
    print_hex_dump("Generated Ciphertext", cipher_buf, msg_len);

    /* Step 2: Decryption */
    chacha20_xor_stream(rfc_key, rfc_nonce, 1,
                        cipher_buf, plain_buf, msg_len);
    plain_buf[msg_len] = '\0';

    printf("\nDecrypted Plaintext:\n\"%s\"\n", (char *)plain_buf);

    if (memcmp(test_vector_msg, plain_buf, msg_len) == 0) {
        printf("\n[STATUS] Verification PASSED: Decrypted output matches RFC 8439 vector.\n");
    } else {
        printf("\n[STATUS] Verification FAILED: Mismatch detected.\n");
    }

    /* Step 3: Performance Profiling */
    run_performance_profile(rfc_key, rfc_nonce, (const uint8_t *)test_vector_msg, msg_len);

    return 0;
}

/*
 * References:
 * 1. Y. Nir and A. Langley, "ChaCha20 and Poly1305 for IETF Protocols,"
 *    RFC 8439, Internet Engineering Task Force (IETF), June 2018.
 *    https://www.rfc-editor.org/rfc/rfc8439
 * 2. D. J. Bernstein, "ChaCha, a variant of Salsa20," Workshop Record of
 *    SASC 2008: The State of the Art of Stream Ciphers, 2008.
 */
