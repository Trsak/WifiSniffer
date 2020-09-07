/**
 * @file sniffer_libtins.h
 * @author Petr Sopf (xsopfp00)
 * @brief Libtins sniffer class
 */
 
#ifndef SNIFFER_SNIFFER_LIBTINS_H
#define SNIFFER_SNIFFER_LIBTINS_H

#include "sniffer.h"

class SnifferLibtins : public BasicSniffer {
private:
    Sniffer *sniffer;
public:
    SnifferLibtins(string interfaceName, string bssid, string clientMac, string encryptionKey, bool onlyPassiveAttack,
                   string saveFile);

    void setFilter(string filter);

    void startSniffing();
};

#endif //SNIFFER_SNIFFER_LIBTINS_H
