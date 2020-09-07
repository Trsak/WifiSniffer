/**
 * @file sniffer.h
 * @author Petr Sopf (xsopfp00)
 * @brief Basic Sniffer class
 */

#ifndef SNIFFER_SNIFFER_H
#define SNIFFER_SNIFFER_H

#include <iostream>
#include <string>
#include <chrono>
#include <tins/tins.h>
#include <pcap.h>

using namespace std;
using namespace Tins;
using namespace Crypto;

class BasicSniffer {
public:
    string interfaceName;
    string ssid;
    string bssid;
    string clientMac;
    string encryptionKey;
    string saveFile;

    int startTime; //Start time of capturing packets
    int apChannel; //AP channel
    int capturedPacketsCount;

    bool shouldAttackOnlyPassive;
    bool isDecrypted = false;

    enum SnifferStep {
        START_SNIFFING,
        CAPTURE_BEACON,
        DECRYPT_START,
        DECRYPT_WEP,
        DECRYPT_WPA,
        SNIFF_NO_ENCRYPTION,
        CLIENT_DEAUTH
    };

    SnifferStep currentStep;

    RSNInformation::CypherSuites encryption;

    PacketWriter *packetWriter;

    Crypto::WPA2Decrypter wpa2Decrypter;
    Crypto::WEPDecrypter decrypter;

    /**
     * @return void
     *
     * Starts sniffing
     */
    virtual void startSniffing() = 0;

    /**
     * @return void
     *
     * Send deauth packets
     */
    void deauthClient();

    /**
     * @return void
     *
     * Gets info about current step
     */
    void getNewStepInfo(SnifferStep lastStep);

    /**
     * @return void
     *
     * Sets sniff filter
     */
    virtual void setFilter(string filter) = 0;

    /**
     * @return string
     *
     * Returns string filter
     */
    string getFilter(bool includeBroadcast);

    /**
     * @return bool
     *
     * Packet processing
     */
    bool processPacket(PDU &pdu);

    /**
     * @return void
     *
     * Captures beacon packet and extracts data from it
     */
    void collectBeacon(PDU &pdu);

    /**
     * @return void
     *
     * Collects packets without encryption
     */
    void collectData(PDU &pdu);

    /**
     * @return void
     *
     * Collects WEP encrypted packets
     */
    void collectDataWEP(PDU &pdu);

    /**
     * @return void
     *
     * Collects WPA encrypted packets
     */
    void collectDataWPA(PDU &pdu);
};

#endif
