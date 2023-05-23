#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <string_view>

union __attribute__((__packed__)) IP {
  uint32_t addr; // network byte order
  uint8_t bytes[4];
  IP() : addr(0) {}
  IP(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    bytes[0] = a;
    bytes[1] = b;
    bytes[2] = c;
    bytes[3] = d;
  }
  // Constructor for address in network byte order
  IP(uint32_t a) : addr(a) {}
  static IP FromInterface(std::string_view interface_name);
  static IP NetmaskFromInterface(std::string_view interface_name);
  std::string to_string() const;
  auto operator<=>(const IP &other) const {
    return (int32_t)ntohl(addr) <=> (int32_t)ntohl(other.addr);
  }
  bool operator==(const IP &other) const { return addr == other.addr; }
  bool operator!=(const IP &other) const { return addr != other.addr; }
  IP operator&(const IP &other) const {
    return IP(addr & other.addr);
  }
  IP operator|(const IP &other) const {
    return IP(addr | other.addr);
  }
  IP operator~() const {
    return IP(~addr);
  }
  IP operator+(int n) const {
    return IP(htonl(ntohl(addr) + n));
  }
  IP &operator++() {
    addr = htonl(ntohl(addr) + 1);
    return *this;
  }
  bool TryParse(const char* cp) {
    return inet_pton(AF_INET, cp, &addr) == 1;
  }
};

struct MAC {
  uint8_t bytes[6];
  MAC() : bytes{0, 0, 0, 0, 0, 0} {}
  MAC(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f)
      : bytes{a, b, c, d, e, f} {}
  MAC(char s[6])
      : bytes{(uint8_t)s[0], (uint8_t)s[1], (uint8_t)s[2],
              (uint8_t)s[3], (uint8_t)s[4], (uint8_t)s[5]} {}
  static MAC FromInterface(std::string_view interface_name);
  std::string to_string() const;
  uint8_t &operator[](int i) { return bytes[i]; }
  bool TryParse(const char* cp) {
    return sscanf(cp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &bytes[0], &bytes[1], &bytes[2],
                  &bytes[3], &bytes[4], &bytes[5]) == 6;
  }
  auto operator<=>(const MAC &other) const {
    return memcmp(bytes, other.bytes, 6);
  }
};
