#pragma once

#include <string_view>
#include <cstdint>

union IP {
  uint32_t addr; // network byte order
  uint8_t bytes[4];
  IP(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    bytes[0] = a;
    bytes[1] = b;
    bytes[2] = c;
    bytes[3] = d;
  }
};

struct MAC {
  uint8_t bytes[6];
  MAC(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f)
      : bytes{a, b, c, d, e, f} {}
  MAC(char s[6])
      : bytes{(uint8_t)s[0], (uint8_t)s[1], (uint8_t)s[2],
              (uint8_t)s[3], (uint8_t)s[4], (uint8_t)s[5]} {}
  static MAC FromInterface(std::string_view interface_name);
};
