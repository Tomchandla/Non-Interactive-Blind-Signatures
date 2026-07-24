#include <cstdio>
#include <cstdint>
extern "C" void nibs_lowmc_port_kat(const uint8_t*, const uint8_t*, uint8_t*);
int main(){
    for (int t = 0; t < 4; ++t) {
        uint8_t key[10], pt[32], ct[32];
        for (int i = 0; i < 10; ++i) key[i] = (uint8_t)(t*31 + i*7 + 1);
        for (int i = 0; i < 32; ++i) pt[i]  = (uint8_t)(t*17 + i*5 + 3);
        nibs_lowmc_port_kat(key, pt, ct);
        for (int i = 0; i < 32; ++i) printf("%02x", ct[i]);
        printf("\n");
    }
}
