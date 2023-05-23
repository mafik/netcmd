// NetworkCommander is a DHCP, proxy DNS & mDNS server for home networks. It's
// designed to run on the gateway router of a home network. It's web interface
// allows the user to easily inspect the state of the network - what devices are
// connected, snoop on DNS requests by IoT devices, check NAT masquerades,
// forward ports, etc.

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <map>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "epoll.hh"
#include "hex.hh"
#include "log.hh"
#include "net_types.hh"
#include "random.hh"

using namespace std;

// User Config
const string kInterfaceName = "enxe8802ee74415"; // "enp0s31f6";
const string kDomainName = "local";

// Default values, which will be overwritten during startup.
// Those values could actually be fetched from the kernel each time they're
// needed. This might be useful if the network configuration changes while the
// program is running. If this ever becomes a problem, just remove those
// variables.
IP server_ip = {192, 168, 1, 1};
IP netmask = {255, 255, 255, 0};
vector<IP> dns_servers = {IP{8, 8, 8, 8}, IP{8, 8, 4, 4}};

// Prefix each line with `spaces` spaces.
std::string IndentString(std::string in, int spaces = 2) {
  std::string out(spaces, ' ');
  for (char c : in) {
    out += c;
    if (c == '\n') {
      for (int i = 0; i < spaces; ++i) {
        out += ' ';
      }
    }
  }
  return out;
}

void SetNonBlocking(int fd, string &error) {
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) {
    error = "fcntl(F_GETFL) failed: ";
    error += strerror(errno);
    return;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    error = "fcntl(F_SETFL) failed: ";
    error += strerror(errno);
    return;
  }
}

map<IP, vector<string>> ReadEtcHosts() {
  map<IP, vector<string>> etc_hosts;
  std::ifstream hosts_stream("/etc/hosts");
  std::string line;
  while (std::getline(hosts_stream, line)) {
    if (auto pos = line.find("#"); pos != string::npos) {
      line.resize(pos);
    }
    std::istringstream iss(line);
    std::string ip_str;
    if (!(iss >> ip_str)) {
      continue;
    }
    IP ip;
    if (!ip.TryParse(ip_str.c_str())) {
      continue;
    }
    std::string hostname;
    while (iss >> hostname) {
      etc_hosts[ip].push_back(hostname);
    }
  }
  return etc_hosts;
}

map<MAC, IP> ReadEtcEthers(const map<IP, vector<string>> &etc_hosts) {
  map<MAC, IP> etc_ethers;
  std::ifstream ethers_stream("/etc/ethers");
  std::string line;
  while (std::getline(ethers_stream, line)) {
    if (auto pos = line.find("#"); pos != string::npos) {
      line.resize(pos);
    }
    std::istringstream iss(line);
    std::string mac_str;
    std::string addr_str;
    if (!(iss >> mac_str >> addr_str)) {
      continue;
    }
    MAC mac;
    if (!mac.TryParse(mac_str.c_str())) {
      continue;
    }
    IP ip;
    if (ip.TryParse(addr_str.c_str())) {
      etc_ethers[mac] = ip;
    } else {
      for (auto it : etc_hosts) {
        for (auto hostname : it.second) {
          if (hostname == addr_str) {
            etc_ethers[mac] = it.first;
            goto outer;
          }
        }
      }
    outer:
    }
  }
  return etc_ethers;
}

using chrono::steady_clock;

namespace rfc1700 {

const char *kHardwareTypeNames[] = {"Not hardware address",
                                    "Ethernet (10Mb)",
                                    "Experimental Ethernet (3Mb)",
                                    "Amateur Radio AX.25",
                                    "Proteon ProNET Token Ring",
                                    "Chaos",
                                    "IEEE 802 Networks",
                                    "ARCNET",
                                    "Hyperchannel",
                                    "Lanstar",
                                    "Autonet Short Address",
                                    "LocalTalk",
                                    "LocalNet (IBM PCNet or SYTEK LocalNET)",
                                    "Ultra link",
                                    "SMDS",
                                    "Frame Relay",
                                    "Asynchronous Transmission Mode (ATM)",
                                    "HDLC",
                                    "Fibre Channel",
                                    "Asynchronous Transmission Mode (ATM)",
                                    "Serial Line",
                                    "Asynchronous Transmission Mode (ATM)"};

string HardwareTypeToString(uint8_t type) {
  if (type < sizeof(kHardwareTypeNames) / sizeof(kHardwareTypeNames[0])) {
    return kHardwareTypeNames[type];
  }
  return "Unknown hardware type " + std::to_string(type);
}

} // namespace rfc1700

namespace arp {

struct IOCtlRequest {
  struct sockaddr_in protocol_address;
  struct sockaddr hardware_address;
  int flags;
  struct sockaddr netmask; /* Only for proxy arps.  */
  char device[16];
};

static_assert(sizeof(IOCtlRequest) == sizeof(arpreq),
              "IOCtlRequest doesn't match `struct arpreq` from <net/if_arp.h>");

void Set(IP ip, MAC mac, int af_inet_fd, string &error) {
  IOCtlRequest r{
      .protocol_address = {.sin_family = AF_INET,
                           .sin_addr = {.s_addr = ip.addr}},
      .hardware_address = {.sa_family = AF_UNSPEC,
                           .sa_data = {(char)mac[0], (char)mac[1], (char)mac[2],
                                       (char)mac[3], (char)mac[4],
                                       (char)mac[5]}},
      .flags = ATF_COM,
  };
  strncpy(r.device, kInterfaceName.c_str(), sizeof(r.device));
  if (ioctl(af_inet_fd, SIOCSARP, &r) < 0) {
    error = "ioctl(SIOCSARP) failed: " + string(strerror(errno));
  }
}

} // namespace arp

namespace dhcp {

const IP kBroadcastIP(255, 255, 255, 255);
const uint16_t kServerPort = 67;
const uint16_t kClientPort = 68;
const uint32_t kMagicCookie = 0x63825363;

namespace options {

// RFC 2132
enum OptionCode : uint8_t {
  OptionCode_Pad = 0,
  OptionCode_SubnetMask = 1,
  OptionCode_TimeOffset = 2,
  OptionCode_Router = 3,
  OptionCode_TimeServer = 4,
  OptionCode_NameServer = 5,
  OptionCode_DomainNameServer = 6,
  OptionCode_LogServer = 7,
  OptionCode_CookieServer = 8,
  OptionCode_LPRServer = 9,
  OptionCode_ImpressServer = 10,
  OptionCode_ResourceLocationServer = 11,
  OptionCode_HostName = 12,
  OptionCode_BootFileSize = 13,
  OptionCode_MeritDumpFile = 14,
  OptionCode_DomainName = 15,
  OptionCode_SwapServer = 16,
  OptionCode_RootPath = 17,
  OptionCode_ExtensionsPath = 18,
  OptionCode_IPForwarding = 19,
  OptionCode_NonLocalSourceRouting = 20,
  OptionCode_PolicyFilter = 21,
  OptionCode_MaximumDatagramReassemblySize = 22,
  OptionCode_DefaultIPTimeToLive = 23,
  OptionCode_PathMTUAgingTimeout = 24,
  OptionCode_PathMTUPlateauTable = 25,
  OptionCode_InterfaceMTU = 26,
  OptionCode_AllSubnetsAreLocal = 27,
  OptionCode_BroadcastAddress = 28,
  OptionCode_PerformMaskDiscovery = 29,
  OptionCode_MaskSupplier = 30,
  OptionCode_PerformRouterDiscovery = 31,
  OptionCode_RouterSolicitationAddress = 32,
  OptionCode_StaticRoute = 33,
  OptionCode_TrailerEncapsulation = 34,
  OptionCode_ARPCacheTimeout = 35,
  OptionCode_EthernetEncapsulation = 36,
  OptionCode_TCPDefaultTTL = 37,
  OptionCode_TCPKeepaliveInterval = 38,
  OptionCode_TCPKeepaliveGarbage = 39,
  OptionCode_NetworkInformationServiceDomain = 40,
  OptionCode_NetworkInformationServers = 41,
  OptionCode_NTPServers = 42,
  OptionCode_VendorSpecificInformation = 43,
  OptionCode_NetBIOSOverTCPIPNameServer = 44,
  OptionCode_NetBIOSOverTCPIPDatagramDistributionServer = 45,
  OptionCode_NetBIOSOverTCPIPNodeType = 46,
  OptionCode_NetBIOSOverTCPIPScope = 47,
  OptionCode_XWindowSystemFontServer = 48,
  OptionCode_XWindowSystemDisplayManager = 49,
  OptionCode_RequestedIPAddress = 50,
  OptionCode_IPAddressLeaseTime = 51,
  OptionCode_Overload = 52,
  OptionCode_MessageType = 53,
  OptionCode_ServerIdentifier = 54,
  OptionCode_ParameterRequestList = 55,
  OptionCode_Message = 56,
  OptionCode_MaximumDHCPMessageSize = 57,
  OptionCode_RenewalTimeValue = 58,
  OptionCode_RebindingTimeValue = 59,
  OptionCode_VendorClassIdentifier = 60,
  OptionCode_ClientIdentifier = 61,
  OptionCode_NetworkInformationServicePlusDomain = 64,
  OptionCode_NetworkInformationServicePlusServers = 65,
  OptionCode_TFTPServerName = 66,
  OptionCode_BootfileName = 67,
  OptionCode_MobileIPHomeAgent = 68,
  OptionCode_SimpleMailTransportProtocol = 69,
  OptionCode_PostOfficeProtocolServer = 70,
  OptionCode_NetworkNewsTransportProtocol = 71,
  OptionCode_DefaultWorldWideWebServer = 72,
  OptionCode_DefaultFingerServer = 73,
  OptionCode_DefaultInternetRelayChatServer = 74,
  OptionCode_StreetTalkServer = 75,
  OptionCode_StreetTalkDirectoryAssistance = 76,
  OptionCode_DomainSearch = 119,
  OptionCode_ClasslessStaticRoute = 121,
  OptionCode_PrivateClasslessStaticRoute = 249,
  OptionCode_PrivateProxyAutoDiscovery = 252,
  OptionCode_End = 255,
};

string OptionCodeToString(OptionCode code) {
  switch (code) {
  case OptionCode_Pad:
    return "Pad";
  case OptionCode_SubnetMask:
    return "Subnet Mask";
  case OptionCode_TimeOffset:
    return "Time Offset";
  case OptionCode_Router:
    return "Router";
  case OptionCode_TimeServer:
    return "Time Server";
  case OptionCode_NameServer:
    return "Name Server";
  case OptionCode_DomainNameServer:
    return "Domain Name Server";
  case OptionCode_LogServer:
    return "Log Server";
  case OptionCode_CookieServer:
    return "Cookie Server";
  case OptionCode_LPRServer:
    return "LPR Server";
  case OptionCode_ImpressServer:
    return "Impress Server";
  case OptionCode_ResourceLocationServer:
    return "Resource Location Server";
  case OptionCode_HostName:
    return "Host Name";
  case OptionCode_BootFileSize:
    return "Boot File Size";
  case OptionCode_MeritDumpFile:
    return "Merit Dump File";
  case OptionCode_DomainName:
    return "Domain Name";
  case OptionCode_SwapServer:
    return "Swap Server";
  case OptionCode_RootPath:
    return "Root Path";
  case OptionCode_ExtensionsPath:
    return "Extensions Path";
  case OptionCode_IPForwarding:
    return "IP Forwarding Enable/Disable";
  case OptionCode_NonLocalSourceRouting:
    return "Non-Local Source Routing Enable/Disable";
  case OptionCode_PolicyFilter:
    return "Policy Filter";
  case OptionCode_MaximumDatagramReassemblySize:
    return "Maximum Datagram Reassembly Size";
  case OptionCode_DefaultIPTimeToLive:
    return "Default IP Time To Live";
  case OptionCode_PathMTUAgingTimeout:
    return "Path MTU Aging Timeout";
  case OptionCode_PathMTUPlateauTable:
    return "Path MTU Plateau Table";
  case OptionCode_InterfaceMTU:
    return "Interface MTU";
  case OptionCode_AllSubnetsAreLocal:
    return "All Subnets Are Local";
  case OptionCode_BroadcastAddress:
    return "Broadcast Address";
  case OptionCode_PerformMaskDiscovery:
    return "Perform Mask Discovery";
  case OptionCode_MaskSupplier:
    return "Mask Supplier";
  case OptionCode_PerformRouterDiscovery:
    return "Perform Router Discovery";
  case OptionCode_RouterSolicitationAddress:
    return "Router Solicitation Address";
  case OptionCode_StaticRoute:
    return "Static Route";
  case OptionCode_TrailerEncapsulation:
    return "Trailer Encapsulation";
  case OptionCode_ARPCacheTimeout:
    return "ARP Cache Timeout";
  case OptionCode_EthernetEncapsulation:
    return "Ethernet Encapsulation";
  case OptionCode_TCPDefaultTTL:
    return "TCP Default TTL";
  case OptionCode_TCPKeepaliveInterval:
    return "TCP Keepalive Interval";
  case OptionCode_TCPKeepaliveGarbage:
    return "TCP Keepalive Garbage";
  case OptionCode_NetworkInformationServiceDomain:
    return "Network Information Service Domain";
  case OptionCode_NetworkInformationServers:
    return "Network Information Servers";
  case OptionCode_NTPServers:
    return "NTP Servers";
  case OptionCode_VendorSpecificInformation:
    return "Vendor Specific Information";
  case OptionCode_NetBIOSOverTCPIPNameServer:
    return "NetBIOS over TCP/IP Name Server";
  case OptionCode_NetBIOSOverTCPIPDatagramDistributionServer:
    return "NetBIOS over TCP/IP Datagram Distribution Server";
  case OptionCode_NetBIOSOverTCPIPNodeType:
    return "NetBIOS over TCP/IP Node Type";
  case OptionCode_NetBIOSOverTCPIPScope:
    return "NetBIOS over TCP/IP Scope";
  case OptionCode_XWindowSystemFontServer:
    return "X Window System Font Server";
  case OptionCode_XWindowSystemDisplayManager:
    return "X Window System Display Manager";
  case OptionCode_RequestedIPAddress:
    return "Requested IP Address";
  case OptionCode_IPAddressLeaseTime:
    return "IP Address Lease Time";
  case OptionCode_Overload:
    return "Overload";
  case OptionCode_MessageType:
    return "Message Type";
  case OptionCode_ServerIdentifier:
    return "Server Identifier";
  case OptionCode_ParameterRequestList:
    return "Parameter Request List";
  case OptionCode_Message:
    return "Message";
  case OptionCode_MaximumDHCPMessageSize:
    return "Maximum DHCP Message Size";
  case OptionCode_RenewalTimeValue:
    return "Renewal (T1) Time Value";
  case OptionCode_RebindingTimeValue:
    return "Rebinding (T2) Time Value";
  case OptionCode_VendorClassIdentifier:
    return "Vendor Class Identifier";
  case OptionCode_ClientIdentifier:
    return "Client Identifier";
  case OptionCode_NetworkInformationServicePlusDomain:
    return "Network Information Service+ Domain";
  case OptionCode_NetworkInformationServicePlusServers:
    return "Network Information Service+ Servers";
  case OptionCode_TFTPServerName:
    return "TFTP Server Name";
  case OptionCode_BootfileName:
    return "Bootfile Name";
  case OptionCode_MobileIPHomeAgent:
    return "Mobile IP Home Agent";
  case OptionCode_SimpleMailTransportProtocol:
    return "Simple Mail Transport Protocol";
  case OptionCode_PostOfficeProtocolServer:
    return "Post Office Protocol Server";
  case OptionCode_NetworkNewsTransportProtocol:
    return "Network News Transport Protocol";
  case OptionCode_DefaultWorldWideWebServer:
    return "Default World Wide Web Server";
  case OptionCode_DefaultFingerServer:
    return "Default Finger Server";
  case OptionCode_DefaultInternetRelayChatServer:
    return "Default Internet Relay Chat Server";
  case OptionCode_StreetTalkServer:
    return "StreetTalk Server";
  case OptionCode_StreetTalkDirectoryAssistance:
    return "StreetTalk Directory Assistance";
  case OptionCode_DomainSearch:
    return "Domain Search";
  case OptionCode_ClasslessStaticRoute:
    return "Classless Static Route";
  case OptionCode_PrivateClasslessStaticRoute:
    return "Private/Classless Static Route (Microsoft)";
  case OptionCode_PrivateProxyAutoDiscovery:
    return "Private/Proxy autodiscovery";
  case OptionCode_End:
    return "End";
  default:
    return "Unknown option code " + std::to_string(code);
  }
}

struct __attribute__((__packed__)) Base {
  OptionCode code;
  uint8_t length;
  Base(OptionCode code, uint8_t length = 0) : code(code), length(length) {}
  string to_string() const;
  size_t size() const {
    switch (code) {
    case 0:
    case 255:
      return 1;
    default:
      return sizeof(*this) + length;
    }
  }
  void write_to(string &buffer) const {
    buffer.append((const char *)this, size());
  }
};

struct __attribute__((__packed__)) SubnetMask : Base {
  const IP ip;
  SubnetMask(const IP &ip) : Base(OptionCode_SubnetMask, 4), ip(ip) {}
  string to_string() const { return "SubnetMask(" + ip.to_string() + ")"; }
};

static_assert(sizeof(SubnetMask) == 6, "SubnetMask is not packed correctly");

struct __attribute__((__packed__)) Router : Base {
  const IP ip;
  Router(const IP &ip) : Base(OptionCode_Router, 4), ip(ip) {}
  string to_string() const { return "Router(" + ip.to_string() + ")"; }
};

struct __attribute__((__packed__)) DomainNameServer : Base {
  IP dns[0];
  static unique_ptr<DomainNameServer> Make(initializer_list<IP> ips) {
    int n = ips.size();
    void *buffer = malloc(sizeof(DomainNameServer) + sizeof(IP) * n);
    auto r = unique_ptr<DomainNameServer>(new (buffer) DomainNameServer(n));
    int i = 0;
    for (auto ip : ips) {
      r->dns[i++] = ip;
    }
    return r;
  }
  string to_string() const {
    int n = length / 4;
    string r = "DomainNameServer(";
    for (int i = 0; i < n; ++i) {
      if (i > 0) {
        r += ", ";
      }
      r += dns[i].to_string();
    }
    r += ")";
    return r;
  }

private:
  DomainNameServer(int dns_count)
      : Base(OptionCode_DomainNameServer, 4 * dns_count) {}
};

struct __attribute__((__packed__)) HostName : Base {
  static constexpr OptionCode kCode = OptionCode_HostName;
  const uint8_t value[0];
  HostName() = delete;
  string to_string() const { return "HostName(" + hostname() + ")"; }
  string hostname() const { return std::string((const char *)value, length); }
};

struct __attribute__((__packed__)) DomainName : Base {
  static constexpr OptionCode kCode = OptionCode_DomainName;
  const uint8_t value[0];
  static unique_ptr<DomainName> Make(string domain_name) {
    int n = domain_name.size();
    void *buffer = malloc(sizeof(DomainName) + n);
    auto r = unique_ptr<DomainName>(new (buffer) DomainName(n));
    memcpy((void*)r->value, domain_name.data(), n);
    return r;
  }
  string domain_name() const { return std::string((const char *)value, length); }
  string to_string() const {
    return "DomainName(" + domain_name() + ")";
  }
private:
  DomainName(int length) : Base(kCode, length) {}
};

struct __attribute__((__packed__)) RequestedIPAddress : Base {
  static constexpr OptionCode kCode = OptionCode_RequestedIPAddress;
  const IP ip;
  RequestedIPAddress(const IP &ip) : Base(kCode, 4), ip(ip) {}
  string to_string() const {
    return "RequestedIPAddress(" + ip.to_string() + ")";
  }
};

struct __attribute__((__packed__)) IPAddressLeaseTime : Base {
  const uint32_t seconds;
  IPAddressLeaseTime(uint32_t seconds)
      : Base(OptionCode_IPAddressLeaseTime, 4), seconds(htonl(seconds)) {}
  string to_string() const {
    return "IPAddressLeaseTime(" + std::to_string(ntohl(seconds)) + ")";
  }
};

struct __attribute__((__packed__)) MessageType : Base {
  enum Value : uint8_t {
    UNKNOWN = 0,
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    DECLINE = 4,
    ACK = 5,
    NAK = 6,
    RELEASE = 7,
    INFORM = 8,
    FORCERENEW = 9,
    LEASEQUERY = 10,
    LEASEUNASSIGNED = 11,
    LEASEUNKNOWN = 12,
    LEASEACTIVE = 13,
    BULKLEASEQUERY = 14,
    LEASEQUERYDONE = 15,
    ACTIVELEASEQUERY = 16,
    LEASEQUERYSTATUS = 17,
    TLS = 18,
    VALUE_COUNT = 19,
  };
  static const char *kValueNames[VALUE_COUNT];
  static string ValueToString(Value value) {
    if (value < VALUE_COUNT) {
      return kValueNames[value];
    }
    return "UNKNOWN";
  }
  const Value value;
  MessageType(Value value) : Base(OptionCode_MessageType, 1), value(value) {}
  string to_string() const {
    return "MessageType(" + ValueToString(value) + ")";
  }
};

const char *MessageType::kValueNames[VALUE_COUNT] = {"UNKNOWN",
                                                     "DISCOVER",
                                                     "OFFER",
                                                     "REQUEST",
                                                     "DECLINE",
                                                     "ACK",
                                                     "NAK",
                                                     "RELEASE",
                                                     "INFORM",
                                                     "FORCERENEW",
                                                     "LEASEQUERY",
                                                     "LEASEUNASSIGNED",
                                                     "LEASEUNKNOWN",
                                                     "LEASEACTIVE",
                                                     "BULKLEASEQUERY",
                                                     "LEASEQUERYDONE",
                                                     "ACTIVELEASEQUERY",
                                                     "LEASEQUERYSTATUS",
                                                     "TLS"};

struct __attribute__((__packed__)) ServerIdentifier : Base {
  const IP ip;
  ServerIdentifier(const IP &ip)
      : Base(OptionCode_ServerIdentifier, 4), ip(ip) {}
  string to_string() const {
    return "ServerIdentifier(" + ip.to_string() + ")";
  }
};

// RFC 2132, section 9.8
struct __attribute__((__packed__)) ParameterRequestList {
  const uint8_t code = 55;
  const uint8_t length;
  const OptionCode c[0];
  string to_string() const {
    string r = "ParameterRequestList(";
    for (int i = 0; i < length; ++i) {
      r += "\n  ";
      r += OptionCodeToString(c[i]);
    }
    r += ")";
    return r;
  }
};

// RFC 2132, section 9.10
struct __attribute__((__packed__)) MaximumDHCPMessageSize {
  const uint8_t code = 57;
  const uint8_t length = 2;
  const uint16_t value = htons(1500);
  string to_string() const {
    return "MaximumDHCPMessageSize(" + std::to_string(ntohs(value)) + ")";
  }
};

struct __attribute__((__packed__)) VendorClassIdentifier {
  const uint8_t code = 60;
  const uint8_t length;
  const uint8_t value[0];
  string to_string() const {
    return "VendorClassIdentifier(" + std::string((const char *)value, length) +
           ")";
  }
};

// RFC 2132, Section 9.14
struct __attribute__((__packed__)) ClientIdentifier : Base {
  static constexpr OptionCode kCode = OptionCode_ClientIdentifier;
  const uint8_t type = 1; // Hardware address
  const MAC hardware_address;
  ClientIdentifier(const MAC &hardware_address)
      : Base(kCode, 1 + 6), hardware_address(hardware_address) {}
  string to_string() const {
    string r = "ClientIdentifier(";
    r += rfc1700::HardwareTypeToString(type);
    r += ", " + hardware_address.to_string() + ")";
    return r;
  }
};

struct __attribute__((__packed__)) End : Base {
  End() : Base(OptionCode_End) {}
};

string Base::to_string() const {
  switch (code) {
  case OptionCode_SubnetMask:
    return ((const options::SubnetMask *)this)->to_string();
  case OptionCode_Router:
    return ((const options::Router *)this)->to_string();
  case OptionCode_DomainNameServer:
    return ((const options::DomainNameServer *)this)->to_string();
  case OptionCode_HostName:
    return ((const options::HostName *)this)->to_string();
  case OptionCode_DomainName:
    return ((const options::DomainName *)this)->to_string();
  case OptionCode_RequestedIPAddress:
    return ((const options::RequestedIPAddress *)this)->to_string();
  case OptionCode_IPAddressLeaseTime:
    return ((const options::IPAddressLeaseTime *)this)->to_string();
  case OptionCode_MessageType:
    return ((const options::MessageType *)this)->to_string();
  case OptionCode_ServerIdentifier:
    return ((const options::ServerIdentifier *)this)->to_string();
  case OptionCode_ParameterRequestList:
    return ((const options::ParameterRequestList *)this)->to_string();
  case OptionCode_MaximumDHCPMessageSize:
    return ((const options::MaximumDHCPMessageSize *)this)->to_string();
  case OptionCode_VendorClassIdentifier:
    return ((const options::VendorClassIdentifier *)this)->to_string();
  case OptionCode_ClientIdentifier:
    return ((const options::ClientIdentifier *)this)->to_string();
  default:
    const uint8_t *data = (const uint8_t *)(this) + sizeof(*this);
    return "\"" + OptionCodeToString(code) + "\" " + std::to_string(length) +
           " bytes: " + hex(data, length);
  }
}

} // namespace options

// Fixed prefix of a DHCP packet. This is followed by a list of options.
// All fields use network byte order.
struct __attribute__((__packed__)) Header {
  uint8_t message_type = 1;  // Boot Request
  uint8_t hardware_type = 1; // Ethernet
  uint8_t hardware_address_length = 6;
  uint8_t hops = 0;
  uint32_t transaction_id = random<uint32_t>();
  uint16_t seconds_elapsed = 0;
  uint16_t flags = 0;
  IP client_ip = {0, 0, 0, 0};  // ciaddr
  IP your_ip = {0, 0, 0, 0};    // yiaddr
  IP server_ip = {0, 0, 0, 0};  // siaddr (Next server IP)
  IP gateway_ip = {0, 0, 0, 0}; // giaddr (Relay agent IP)
  union {
    uint8_t client_hardware_address[16] = {};
    MAC client_mac_address;
  };
  uint8_t server_name[64] = {};
  uint8_t boot_filename[128] = {};
  uint32_t magic_cookie = htonl(kMagicCookie);

  string to_string() const {
    string s = "dhcp::Header {\n";
    s += "  message_type: " + std::to_string(message_type) + "\n";
    s += "  hardware_type: " + rfc1700::HardwareTypeToString(hardware_type) +
         "\n";
    s += "  hardware_address_length: " +
         std::to_string(hardware_address_length) + "\n";
    s += "  hops: " + std::to_string(hops) + "\n";
    s += "  transaction_id: " + hex(&transaction_id, sizeof(transaction_id)) +
         "\n";
    s += "  seconds_elapsed: " + std::to_string(seconds_elapsed) + "\n";
    s += "  flags: " + std::to_string(ntohs(flags)) + "\n";
    s += "  client_ip: " + client_ip.to_string() + "\n";
    s += "  your_ip: " + your_ip.to_string() + "\n";
    s += "  server_ip: " + server_ip.to_string() + "\n";
    s += "  gateway_ip: " + gateway_ip.to_string() + "\n";
    s += "  client_mac_address: " + client_mac_address.to_string() + "\n";
    s += "  server_name: " + std::string((const char *)server_name) + "\n";
    s += "  boot_filename: " + std::string((const char *)boot_filename) + "\n";
    s += "  magic_cookie: " + hex(&magic_cookie, sizeof(magic_cookie)) + "\n";
    s += "}";
    return s;
  }

  void write_to(string &buffer) {
    buffer.append((const char *)this, sizeof(*this));
  }
};

// Provides read access to a memory buffer that contains a DHCP packet.
struct __attribute__((__packed__)) PacketView : Header {
  uint8_t options[0];
  void CheckFitsIn(size_t len, string &error) {
    if (len < sizeof(Header)) {
      error = "Packet is too short";
      return;
    }
    if (len < sizeof(Header) + 1) {
      error = "Packet is too short to contain an End option";
      return;
    }
    uint8_t *p = options;
    while (true) {
      options::Base *opt = (options::Base *)p;
      p += opt->size();
      if (opt->code == options::OptionCode_End) {
        break;
      }
    }
    size_t options_size = p - options;
    size_t total_size = sizeof(Header) + options_size;
    if (len < total_size) {
      error = "Packet is too short to contain all the options";
      return;
    }
    // Packets can be padded with 0s at the end - we can ignore them.
  }
  string to_string() const {
    string s = "dhcp::PacketView {\n";
    s += IndentString(Header::to_string());
    s += "\n  options:\n";
    const uint8_t *p = options;
    while (*p != 255) {
      const options::Base &opt = *(const options::Base *)p;
      s += IndentString(opt.to_string(), 4) + "\n";
      p += opt.size();
    }
    s += "}";
    return s;
  }
  options::Base *FindOption(options::OptionCode code) const {
    const uint8_t *p = options;
    while (*p != 255) {
      options::Base &opt = *(options::Base *)p;
      if (opt.code == code) {
        return &opt;
      }
      p += opt.size();
    }
    return nullptr;
  }
  template <class T> T *FindOption() const {
    options::Base *base = FindOption(T::kCode);
    if (base) {
      return (T *)base;
    }
    return nullptr;
  }
  options::MessageType::Value MessageType() const {
    if (options::MessageType *o = (options::MessageType *)FindOption(
            options::OptionCode_MessageType)) {
      return o->value;
    }
    return options::MessageType::UNKNOWN;
  }
  string client_id() const {
    if (auto *opt = FindOption<options::ClientIdentifier>()) {
      opt->hardware_address.to_string();
    }
    return client_mac_address.to_string();
  }
};

struct Server : epoll::Listener {

  struct Entry {
    string client_id;
    string hostname;
    steady_clock::time_point expiration;
  };

  map<IP, Entry> entries;

  void ReadEtcConfig() {
    map<IP, vector<string>> etc_hosts = ReadEtcHosts();
    map<MAC, IP> etc_ethers = ReadEtcEthers(etc_hosts);

    for (auto [mac, ip] : etc_ethers) {
      auto &entry = entries[ip];
      entry.client_id = mac.to_string();
      entry.expiration = steady_clock::time_point::max(); // never expire
      if (auto etc_hosts_it = etc_hosts.find(ip);
          etc_hosts_it != etc_hosts.end()) {
        auto &aliases = etc_hosts_it->second;
        if (!aliases.empty()) {
          entry.hostname = aliases[0];
        }
      }
    }
  }

  // Start listening.
  //
  // To actually accept new connections, make sure to Poll the `epoll`
  // instance after listening.
  void Listen(string &error) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
      error = "socket";
      return;
    }

    SetNonBlocking(fd, error);
    if (!error.empty()) {
      StopListening();
      return;
    }

    int flag = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) <
        0) {
      error = "setsockopt: SO_REUSEADDR";
      StopListening();
      return;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, kInterfaceName.data(),
                   kInterfaceName.size()) < 0) {
      error = "Error when setsockopt bind to device";
      StopListening();
      return;
    };

    sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(kServerPort),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
      error = "bind: ";
      error += strerror(errno);
      StopListening();
      return;
    }

    epoll::Add(this, error);
  }

  // Stop listening.
  void StopListening() {
    string error_ignored;
    epoll::Del(this, error_ignored);
    shutdown(fd, SHUT_RDWR);
    close(fd);
  }

  void SendTo(const string &buffer, IP ip, string &error) {
    sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(kClientPort),
        .sin_addr = {.s_addr = ip.addr},
    };
    if (sendto(fd, buffer.data(), buffer.size(), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
      error = "sendto: " + string(strerror(errno));
    }
  }

  // Function used to validate IP addresses provided by clients.
  bool IsValidClientIP(IP requested_ip) {
    const IP network_ip = server_ip & netmask;
    const IP broadcast_ip = network_ip | ~netmask;
    if (network_ip != (requested_ip & netmask)) {
      // Requested IP outside of our network.
      return false;
    }
    if (requested_ip == network_ip) {
      // Requested IP is the network address.
      return false;
    }
    if (requested_ip == broadcast_ip) {
      // Requested IP is the broadcast address.
      return false;
    }
    if (requested_ip == server_ip) {
      // Requested IP is our own IP.
      return false;
    }
    return true;
  }

  IP ChooseIP(const PacketView &request, string &error) {
    const IP network_ip = server_ip & netmask;
    const IP broadcast_ip = network_ip | ~netmask;
    string client_id = request.client_id();
    // Try to find entry with matching client_id.
    for (auto it : entries) {
      const Entry &entry = it.second;
      if (entry.client_id == client_id) {
        return it.first;
      }
    }
    // Take the requested IP if it is available.
    if (auto *opt = request.FindOption<options::RequestedIPAddress>()) {
      const IP requested_ip = opt->ip;
      bool ok = IsValidClientIP(requested_ip);
      if (!ok) {
        ok = false;
      }
      if (auto it = entries.find(requested_ip); it != entries.end()) {
        Entry &entry = it->second;
        if ((entry.client_id != client_id) &&
            (entry.expiration > steady_clock::now())) {
          // Requested IP is taken by another client.
          ok = false;
        }
      }
      if (ok) {
        return requested_ip;
      }
    }
    // Try to find unused IP.
    for (IP ip = network_ip + 1; ip < broadcast_ip; ++ip) {
      if (ip == server_ip) {
        continue;
      }
      if (auto it = entries.find(ip); it == entries.end()) {
        return ip;
      }
    }
    // Try to find the most expired IP.
    IP oldest_ip(0, 0, 0, 0);
    steady_clock::time_point oldest_expiration =
        steady_clock::time_point::max();
    for (auto it : entries) {
      const Entry &entry = it.second;
      if (entry.expiration < oldest_expiration) {
        oldest_ip = it.first;
        oldest_expiration = entry.expiration;
      }
    }
    if (oldest_expiration < steady_clock::now()) {
      return oldest_ip;
    }
    error = "No IP available";
    return IP(0, 0, 0, 0);
  }

  IP ChooseInformIP(const PacketView &request, string &error) {
    IP ip = request.client_ip;
    if (!IsValidClientIP(ip)) {
      error = "Invalid IP address";
      return IP(0, 0, 0, 0);
    }
    return ip;
  }

  void NotifyRead(string &abort_error) override {
    char recvbuf[65536] = {0};
    int len;
    struct sockaddr_in clientaddr;
    socklen_t clilen = sizeof(struct sockaddr);
    len = recvfrom(fd, recvbuf, sizeof(recvbuf), 0,
                   (struct sockaddr *)&clientaddr, &clilen);
    IP source_ip(clientaddr.sin_addr.s_addr);
    LOG << "Received a message from " << source_ip.to_string();
    if (len < sizeof(PacketView)) {
      ERROR << "DHCP server received a packet that is too short: " << len
            << " bytes:\n"
            << hex(recvbuf, len);
      return;
    }
    PacketView &packet = *(PacketView *)recvbuf;
    string log_error;
    packet.CheckFitsIn(len, log_error);
    if (!log_error.empty()) {
      ERROR << log_error;
      return;
    }
    if (ntohl(packet.magic_cookie) != kMagicCookie) {
      ERROR << "DHCP server received a packet with an invalid magic cookie: "
            << hex(&packet.magic_cookie, sizeof(packet.magic_cookie));
      return;
    }
    if ((packet.server_ip <=> server_ip != 0) &&
        (packet.server_ip <=> IP(0, 0, 0, 0) != 0)) {
      // Silently ignore packets that are not for us.
      return;
    }

    options::MessageType::Value response_type = options::MessageType::UNKNOWN;
    steady_clock::duration lease_time = 0s;
    bool inform = false;

    int request_lease_time_seconds = 60;
    switch (packet.MessageType()) {
    case options::MessageType::DISCOVER:
      response_type = options::MessageType::OFFER;
      lease_time = 10s;
      break;
    case options::MessageType::REQUEST:
      response_type = options::MessageType::ACK;
      lease_time = request_lease_time_seconds * 1s;
      break;
    case options::MessageType::INFORM:
      response_type = options::MessageType::ACK;
      lease_time = 0s;
      inform = true;
      break;
    default:
      response_type = options::MessageType::UNKNOWN;
      break;
    }

    const IP chosen_ip = inform ? IP(0, 0, 0, 0) : ChooseIP(packet, log_error);
    if (!log_error.empty()) {
      ERROR << log_error << "\n" << packet.to_string();
      return;
    }

    if (inform && source_ip != packet.client_ip) {
      ERROR << "DHCP server received an INFORM packet with a mismatching "
               "source IP: "
            << source_ip.to_string() << " (source IP) vs "
            << packet.client_ip.to_string() << " (DHCP client_ip)"
            << "\n"
            << packet.to_string();
      return;
    }

    IP response_ip = inform ? packet.client_ip : chosen_ip;
    if (!IsValidClientIP(response_ip)) {
      ERROR << "DHCP server received a packet with an invalid response IP: "
            << response_ip.to_string() << "\n"
            << packet.to_string();
      return;
    }

    if (source_ip == IP(0, 0, 0, 0)) {
      // Set client MAC in the ARP table
      arp::Set(response_ip, packet.client_mac_address, fd, log_error);
      if (!log_error.empty()) {
        ERROR << "Failed to set the client IP/MAC association in the system "
                 "ARP table: "
              << log_error;
        return;
      }
    }

    if (response_type == options::MessageType::UNKNOWN) {
      LOG << "DHCP server received unknown DHCP message:\n"
          << packet.to_string();
      return;
    }

    // Build response
    string buffer;
    Header{.message_type = 2, // Boot Reply
           .transaction_id = packet.transaction_id,
           .your_ip = chosen_ip,
           .server_ip = server_ip,
           .client_mac_address = packet.client_mac_address}
        .write_to(buffer);

    options::MessageType(response_type).write_to(buffer);
    options::SubnetMask(netmask).write_to(buffer);
    options::Router(server_ip).write_to(buffer);
    if (lease_time > 0s) {
      options::IPAddressLeaseTime(request_lease_time_seconds).write_to(buffer);
    }
    options::DomainName::Make(kDomainName)->write_to(buffer);
    options::ServerIdentifier(server_ip).write_to(buffer);
    options::DomainNameServer::Make({server_ip})->write_to(buffer);
    options::End().write_to(buffer);

    SendTo(buffer, response_ip, log_error);
    if (!log_error.empty()) {
      ERROR << log_error;
      return;
    }

    if (!inform) {
      auto &lease = entries[chosen_ip];
      lease.client_id = packet.client_id();
      lease.expiration = steady_clock::now() + lease_time;
      if (auto opt = packet.FindOption<options::HostName>()) {
        lease.hostname = opt->hostname();
      }
    }
  }

  const char *Name() const override { return "dhcp::Server"; }
};

Server server;

} // namespace dhcp

namespace dns {

void StartServer() {}

} // namespace dns

namespace http {

void StartServer() {}

} // namespace http

int main(int argc, char *argv[]) {
  std::string error;

  epoll::Init();

  res_init();
  dns_servers.clear();
  for (int i = 0; i < _res.nscount; ++i) {
    sockaddr_in &entry = _res.nsaddr_list[i];
    dns_servers.emplace_back(entry.sin_addr.s_addr);
  }

  server_ip = IP::FromInterface(kInterfaceName);
  netmask = IP::NetmaskFromInterface(kInterfaceName);

  dhcp::server.ReadEtcConfig();
  dhcp::server.Listen(error);
  if (!error.empty()) {
    FATAL << "Failed to start DHCP server: " << error;
  }

  dns::StartServer();
  http::StartServer();
  LOG << "Starting epoll::Loop()";
  epoll::Loop(error);
  if (!error.empty()) {
    FATAL << error;
  }
  return 0;
}
