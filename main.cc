// NetworkCommander is a DHCP, proxy DNS & mDNS server for home networks. It's
// designed to run on the gateway router of a home network. It's web interface
// allows the user to easily inspect the state of the network - what devices are
// connected, snoop on DNS requests by IoT devices, check NAT masquerades,
// forward ports, etc.

#include <string>

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <limits>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "hex.h"
#include "net_types.h"
#include "random.h"

using namespace std;

const string kInterfaceName = "enp0s31f6";

namespace dhcp {

// Code for inspiration:
// https://github.com/fycth/DHCP-server-scanner/blob/master/src/dhcpd-detector.c

const IP kServerIP(255, 255, 255, 255);
const uint16_t kServerPort = 67;
const uint16_t kClientPort = 68;

namespace options {
struct __attribute__((__packed__)) MessageType {
  const uint8_t code = 53;
  const uint8_t length = 1;
  const uint8_t value;
  MessageType(uint8_t value) : value(value) {}
};
struct __attribute__((__packed__)) MaximumDHCPMessageSize {
  const uint8_t code = 57;
  const uint8_t length = 2;
  const uint16_t value = htons(1500);
};
struct __attribute__((__packed__)) ClientIdentifier {
  const uint8_t code = 61;
  const uint8_t length = 7;
  const uint8_t type = 1; // Hardware address
  const MAC hardware_address;
  ClientIdentifier(const MAC &hardware_address)
      : hardware_address(hardware_address) {}
};
struct __attribute__((__packed__)) RequestedIPAddress {
  const uint8_t code = 50;
  const uint8_t length = 4;
  const IP ip;
  RequestedIPAddress(const IP &ip) : ip(ip) {}
};
} // namespace options

struct __attribute__((__packed__)) Header {
  const uint8_t message_type = 1;  // Boot Request
  const uint8_t hardware_type = 1; // Ethernet
  const uint8_t hardware_address_length = 6;
  const uint8_t hops = 0;
  const uint32_t transaction_id = random<uint32_t>();
  const uint16_t seconds_elapsed = 0;
  const uint16_t flags = 0;
  const IP client_ip = {0, 0, 0, 0};  // ciaddr
  const IP your_ip = {0, 0, 0, 0};    // yiaddr
  const IP server_ip = {0, 0, 0, 0};  // siaddr (Next server IP)
  const IP gateway_ip = {0, 0, 0, 0}; // giaddr (Relay agent IP)
  union {
    uint8_t client_hardware_address[16] = {};
    MAC client_mac_address;
  };
  const uint8_t server_name[64] = {};
  const uint8_t boot_filename[128] = {};
  const uint8_t magic_cookie[4] = {99, 130, 83, 99};
};

struct __attribute__((__packed__)) RequestPacket : Header {
  const options::MessageType o_message_type = {3}; // DHCP Request
  const options::MaximumDHCPMessageSize o_maximum_dhcp_message_size = {};
  uint8_t parameter_request_list_tag = 55;
  uint8_t parameter_request_list_length = 12;
  uint8_t parameter_request_list_values[12] = {
      1,   // Subnet Mask
      3,   // Router
      28,  // Broadcast Address
      6,   // DNS
      15,  // Domain Name
      44,  // NetBIOS over TCP/IP Name Server
      46,  // NetBIOS over TCP/IP Node Type
      47,  // NetBIOS over TCP/IP Scope
      31,  // Perform Router Discovery
      33,  // Static Route
      121, // Classless Static Route
      43}; // Vendor Specific Information
  const uint8_t end = 255;
};

sockaddr_in sender_sockaddr = {
    .sin_family = AF_INET,
    .sin_port = htons(kServerPort),
    .sin_addr = {kServerIP.addr},
};

sockaddr_in listener_sockaddr = {
    .sin_family = AF_INET,
    .sin_port = htons(kClientPort),
    .sin_addr = {htonl(INADDR_ANY)},
};

void Request() {

  int dhcp_socket;
  if ((dhcp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    perror("dhcp_socket/socket");
    exit(1);
  }

  int flag = 1;
  if (setsockopt(dhcp_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&flag,
                 sizeof flag) < 0) {
    perror("dhcp_socket/setsockopt: SO_REUSEADDR");
    exit(1);
  }

  if (setsockopt(dhcp_socket, SOL_SOCKET, SO_BROADCAST, (char *)&flag,
                 sizeof flag) < 0) {
    perror("dhcp_socket/setsockopt: SO_BROADCAST");
    exit(1);
  }

  if (bind(dhcp_socket, (struct sockaddr *)&dhcp::listener_sockaddr,
           sizeof dhcp::listener_sockaddr) < 0) {
    perror("bind");
    exit(1);
  }

  dhcp::RequestPacket request_packet = {};
  request_packet.client_mac_address = MAC::FromInterface(kInterfaceName);
  ssize_t sent = sendto(dhcp_socket, &request_packet, sizeof(request_packet), 0,
                        (struct sockaddr *)&dhcp::sender_sockaddr,
                        sizeof(dhcp::sender_sockaddr));
  if (sent <= 0) {
    perror("sendto");
    exit(1);
  }
  printf("Sent DHCP request (%ld B)\n", sent);
}

} // namespace dhcp

int main(int argc, char *argv[]) {
  dhcp::StartServer();
  dns::StartServer();
  mdns::StartServer();
  http::StartServer();
  Loop();
  return 0;
}