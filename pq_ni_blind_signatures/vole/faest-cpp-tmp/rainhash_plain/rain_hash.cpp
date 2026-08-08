#include <cstring>
#include <chrono>
#include <iostream>

#include "rain_hash.h"


// g++ -march=native -O3 rain_hash.cpp -o rain_hash

int main() {

    std::array<uint8_t, 64> in;
    std::array<uint8_t, 64> out;
    memset(in.data(), 0, 64);
    memset(out.data(), 0, 64);

    for (size_t i = 0; i < 1000; i++) {
        rain_hash(in.data(), out.data());
        memcpy(in.data(), out.data(), 64);
    }
    size_t itr = 1954;
    double total = 0;
    for (size_t i = 0; i < itr; i++) {

        auto start = std::chrono::high_resolution_clock::now();
        rain_hash(in.data(), out.data());
        auto end = std::chrono::high_resolution_clock::now();
        memcpy(in.data(), out.data(), 64);

        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        total += double(ns);
    }
    std::cout << "512bits - rain_hash 512b state 512b sbox - time: " << total / itr << " nanosec\n";
    std::cout << "1Mbits - rain_hash 512b state 512b sbox - time: " << total / 1000 << " microsec\n";



    for (size_t i = 0; i < 1000; i++) {
        rain_hash(in.data(), out.data());
        memcpy(in.data(), out.data(), 64);
    }
    total = 0;
    for (size_t i = 0; i < itr; i++) {

        auto start = std::chrono::high_resolution_clock::now();
        rain_hash_small_256_sbox(in.data(), out.data());
        auto end = std::chrono::high_resolution_clock::now();
        memcpy(in.data(), out.data(), 64);

        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        total += double(ns);
    }
    std::cout << "512bits - rain_hash 512b state 256b x2 sbox - time: " << total / itr << " nanosec\n";
    std::cout << "1Mbits - rain_hash 512b state 256b x2 sbox - time: " << total / 1000 << " microsec\n";


    std::array<uint8_t, 32> in_256;
    std::array<uint8_t, 32> out_256;
    memset(in_256.data(), 0, 32);
    memset(out_256.data(), 0, 32);

    for (size_t i = 0; i < 1000; i++) {
        rain_hash_256(in_256.data(), out_256.data());
        memcpy(in_256.data(), out_256.data(), 32);
    }
    total = 0;
    for (size_t i = 0; i < itr; i++) {

        auto start = std::chrono::high_resolution_clock::now();
        rain_hash_256(in_256.data(), out_256.data());
        auto end = std::chrono::high_resolution_clock::now();
        memcpy(in_256.data(), out_256.data(), 32);

        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        total += double(ns);
    }
    std::cout << "512bits - rain_hash 256b state 256b sbox - time: " << total / itr << " nanosec\n";
    std::cout << "1Mbits - rain_hash 256b state 256b sbox - time: " << total / 1000 << " microsec\n";



    return 0;
}