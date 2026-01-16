#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

typedef struct {
    uint32_t code;
    uint8_t *cur;
    uint8_t *end;
    int leftbits;
} oapv_bs_t;

// Original 8-bit refill logic
uint32_t test_8bit(oapv_bs_t *bs, int count) {
    uint32_t acc = 0;
    for(int i=0; i<count; i++) {
        if(bs->leftbits == 0) {
            bs->code = *((bs)->cur++) << 24;
            bs->leftbits = 8;
        }
        bs->code <<= 1;
        bs->leftbits -= 1;
        acc ^= bs->code; // Prevent optimization
        if (bs->cur >= bs->end - 4) bs->cur = bs->end - 1000;
    }
    return acc;
}

// Optimized 32-bit refill logic
uint32_t test_32bit(oapv_bs_t *bs, int count) {
    uint32_t acc = 0;
    for(int i=0; i<count; i++) {
        if(bs->leftbits == 0) {
            if (bs->cur + 4 <= bs->end) {
                uint32_t _val;
                memcpy(&_val, bs->cur, 4);
                bs->code = __builtin_bswap32(_val);
                bs->cur += 4;
                bs->leftbits = 32;
            } else {
                 bs->code = *((bs)->cur++) << 24;
                 bs->leftbits = 8;
            }
        }
        bs->code <<= 1;
        bs->leftbits -= 1;
        acc ^= bs->code;
        if (bs->cur >= bs->end - 4) bs->cur = bs->end - 1000;
    }
    return acc;
}

double get_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main() {
    uint8_t *buffer = (uint8_t*)malloc(2000);
    memset(buffer, 0xAA, 2000); // Random data
    
    oapv_bs_t bs;
    const int ITER = 500000000; // 500M iterations

    // Test 8-bit
    bs.cur = buffer;
    bs.end = buffer + 2000;
    bs.leftbits = 0;
    double start = get_time_sec();
    uint32_t r1 = test_8bit(&bs, ITER);
    double duration_8bit = get_time_sec() - start;
    printf("Original (8-bit): %.4f sec (checksum: %x)\n", duration_8bit, r1);

    // Test 32-bit
    bs.cur = buffer;
    bs.end = buffer + 2000;
    bs.leftbits = 0;
    start = get_time_sec();
    uint32_t r2 = test_32bit(&bs, ITER);
    double duration_32bit = get_time_sec() - start;
    printf("Optimized (32-bit): %.4f sec (checksum: %x)\n", duration_32bit, r2);
    
    printf("Raw Speedup: %.2fx\n", duration_8bit / duration_32bit);
    return 0;
}
