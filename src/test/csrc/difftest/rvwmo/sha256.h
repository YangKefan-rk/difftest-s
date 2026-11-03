#ifndef DIFFTEST_RVWMO_SHA256_H
#define DIFFTEST_RVWMO_SHA256_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace rvwmo {

// Self-contained SHA-256 for binding a checker-issued marker to sidecar bytes.
// This avoids introducing a simulator link-time dependency on libcrypto.
class Sha256 {
public:
  void update(const uint8_t *bytes, size_t size) {
    for (size_t index = 0; index < size; ++index) {
      block_[buffered_++] = bytes[index];
      if (buffered_ == block_.size()) {
        compress();
        buffered_ = 0;
      }
    }
    length_ += size;
  }

  std::string finish() {
    const uint64_t bit_length = length_ * 8;
    block_[buffered_++] = 0x80;
    if (buffered_ > 56) {
      while (buffered_ < block_.size())
        block_[buffered_++] = 0;
      compress();
      buffered_ = 0;
    }
    while (buffered_ < 56)
      block_[buffered_++] = 0;
    for (unsigned byte = 0; byte < 8; ++byte)
      block_[56 + byte] = uint8_t(bit_length >> (56 - byte * 8));
    compress();
    constexpr char alphabet[] = "0123456789abcdef";
    std::string digest;
    digest.reserve(64);
    for (uint32_t word : state_)
      for (unsigned nibble = 0; nibble < 8; ++nibble) {
        const uint8_t digit = (word >> (28 - nibble * 4)) & 15;
        digest.push_back(alphabet[digit]);
      }
    return digest;
  }

private:
  static uint32_t rotate_right(uint32_t value, unsigned bits) {
    return value >> bits | value << (32 - bits);
  }
  void compress() {
    static constexpr uint32_t constants[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t schedule[64];
    for (unsigned word = 0; word < 16; ++word) {
      schedule[word] = uint32_t(block_[word * 4]) << 24 | uint32_t(block_[word * 4 + 1]) << 16 |
                       uint32_t(block_[word * 4 + 2]) << 8 | uint32_t(block_[word * 4 + 3]);
    }
    for (unsigned word = 16; word < 64; ++word) {
      const uint32_t x = schedule[word - 15];
      const uint32_t y = schedule[word - 2];
      schedule[word] = schedule[word - 16] + (rotate_right(x, 7) ^ rotate_right(x, 18) ^ x >> 3) +
                       schedule[word - 7] + (rotate_right(y, 17) ^ rotate_right(y, 19) ^ y >> 10);
    }
    auto a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    auto e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (unsigned word = 0; word < 64; ++word) {
      const uint32_t choose = (e & f) ^ (~e & g);
      const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t first = h + (rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)) +
                             choose + constants[word] + schedule[word];
      const uint32_t second = (rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)) + majority;
      h = g; g = f; f = e; e = d + first;
      d = c; c = b; b = a; a = first + second;
    }
    const uint32_t work[8] = {a, b, c, d, e, f, g, h};
    for (unsigned word = 0; word < 8; ++word)
      state_[word] += work[word];
  }
  std::array<uint32_t, 8> state_{{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}};
  std::array<uint8_t, 64> block_{};
  uint64_t length_ = 0;
  size_t buffered_ = 0;
};

} // namespace rvwmo
#endif
