/**
 * @file sniffer_libpcap.h
 * @author Petr Sopf (xsopfp00)
 * @brief Libpcap sniffer class
 */
 
#ifndef SNIFFER_SNIFFER_LIBPCAP_H
#define SNIFFER_SNIFFER_LIBPCAP_H

#include "sniffer.h"

using namespace Tins;
using namespace Crypto;

class SnifferLibpcap : public BasicSniffer {
private:
    pcap_t *handler;
public:
    SnifferLibpcap(string interfaceName, string bssid, string clientMac, string encryptionKey, bool onlyPassiveAttack,
                   string saveFile);

    void setFilter(string filter);

    [[noreturn]] void startSniffing();
};

#endif //SNIFFER_SNIFFER_LIBPCAP_H
