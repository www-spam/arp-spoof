#pragma once
#include <cstdint>

#define MAC_LEN 6
#define IP_LEN  4

#pragma pack(push, 1)
struct EthHdr {
    uint8_t dmac[MAC_LEN];
    uint8_t smac[MAC_LEN];
    uint16_t type;
};

struct ArpHdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t  hln;
    uint8_t  pln;
    uint16_t op;
    uint8_t  smac[MAC_LEN];
    uint8_t  sip[IP_LEN];
    uint8_t  tmac[MAC_LEN];
    uint8_t  tip[IP_LEN];
};


struct IpHdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
#pragma pack(pop)
