#include "net_types.hh"

#include <string>
#include <cstring>

#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "format.hh"

IP IP::FromInterface(std::string_view interface_name) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  ioctl(sock, SIOCGIFADDR, &ifr);
  close(sock);
  return IP(((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);
}

IP IP::NetmaskFromInterface(std::string_view interface_name) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  ioctl(sock, SIOCGIFNETMASK, &ifr);
  close(sock);
  return IP(((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);
}

MAC MAC::FromInterface(std::string_view interface_name) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  ioctl(sock, SIOCGIFHWADDR, &ifr);
  close(sock);
  return MAC(ifr.ifr_hwaddr.sa_data);
}

std::string IP::to_string() const {
  return f("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

std::string MAC::to_string() const {
  return f("%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2],
           bytes[3], bytes[4], bytes[5]);
}