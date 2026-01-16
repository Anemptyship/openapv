#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t code;
    uint8_t *cur;
    uint8_t *end;
    int leftbits;
} oapv_bs_t;

void test_8bit(oapv_bs_t *bs) {
    int i;
    for(i=0; i<32; i++) {
        if(bs->leftbits == 0) {
            bs->code = *((bs)->cur++) << 24;
            bs->leftbits = 8;
        }
        bs->code <<= 1;
        bs->leftbits -= 1;
    }
}

void test_32bit(oapv_bs_t *bs) {
    int i;
    for(i=0; i<32; i++) {
        if(bs->leftbits == 0) {
            // Manual inline of optimized macro for fair comparison
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
    }
}
