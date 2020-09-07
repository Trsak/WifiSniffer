/**
 * @file sniffer_libpcap.cpp
 * @author Petr Sopf (xsopfp00)
 * @brief Implementation of libpcap sniffer
 */

#include <iostream>
#include "sniffer_libpcap.h"

using namespace std;

SnifferLibpcap::SnifferLibpcap(string interfaceNameA, string bssidA, string clientMacA,
                               string encryptionKeyA, bool onlyPassiveAttackA, string saveFileA) {
    interfaceName = interfaceNameA;
    bssid = bssidA;
    clientMac = clientMacA;
    encryptionKey = encryptionKeyA;
    currentStep = CAPTURE_BEACON;
    capturedPacketsCount = 0;
    shouldAttackOnlyPassive = onlyPassiveAttackA;
    saveFile = saveFileA;
    packetWriter = new PacketWriter(saveFile, DataLinkType<RadioTap>());
}

[[noreturn]] void SnifferLibpcap::startSniffing() {
    //Create PCAP error buffer
    char errorBuffer[PCAP_ERRBUF_SIZE];

    //Create new PCAP handler
    handler = pcap_create(interfaceName.c_str(), errorBuffer);
    if (handler == nullptr) {
        cerr << "Error: Failed to use selected interface: " << errorBuffer << "." << endl;
        exit(1);
    }

    pcap_set_rfmon(handler, 1); //Enable monitor mode
    pcap_set_snaplen(handler, 2048);  //Set the snapshot length to 2048
    pcap_set_promisc(handler, 0); //Turn off promiscuous mode f
    pcap_set_timeout(handler, 512); //Set the timeout to 512 milliseconds
    pcap_set_immediate_mode(handler, true);  //Enable immediate mode

    //Set nonblocking
    if (pcap_setnonblock(handler, 1, errorBuffer) == -1) {
        cerr << "Error: Could not set non blocking: " << pcap_geterr(handler) << endl;
        exit(1);
    }

    int status = pcap_activate(handler); //Activate handler with given settings
    if (status != 0) { //Process errors
        bool endProcess = true;

        switch (status) {
            case PCAP_ERROR_ACTIVATED:
                cerr << "Error: Handle is already activated!" << endl;
                break;
            case PCAP_ERROR_NO_SUCH_DEVICE:
                cerr << "Error: Interface " << interfaceName << " was not found!" << endl;
                break;
            case PCAP_ERROR_PERM_DENIED:
                cerr << "Error: Insufficient permissions to enable monitor mode!" << endl;
                break;
            case PCAP_ERROR_PROMISC_PERM_DENIED:
                cerr << "Error: Insufficient permissions to enable promiscuous mode!" << endl;
                break;
            case PCAP_ERROR_RFMON_NOTSUP:
                cerr << "Error: Selected interface does not support monitor mode!" << endl;
                break;
            case PCAP_ERROR_IFACE_NOT_UP:
                cerr << "Error: Selected interface is not turned on!" << endl;
                break;
            case PCAP_ERROR:
                cerr << "Error: Could not setup interface: " << pcap_geterr(handler) << endl;
                break;
            default:
                endProcess = false;
                break;
        }

        //End program only on fatal errors, not on warnings
        if (endProcess) {
            exit(1);
        }
    }

    //Set filter
    setFilter(getFilter(true));

    //Set datalink to IEEE 802.11 radio
    if (pcap_set_datalink(handler, DLT_IEEE802_11_RADIO) == -1) {
        cerr << "Error: Could not setup IEEE 802.11 capture: " << pcap_geterr(handler) << endl;
        exit(1);
    }

    cout << "Interface " << interfaceName << " was set to monitor mode." << endl << endl;

    //Start PCAP loop
    SnifferStep lastStep = START_SNIFFING;
    while (true) {
        if (lastStep != currentStep) {
            getNewStepInfo(lastStep);
            lastStep = currentStep;
        }

        if (currentStep == CLIENT_DEAUTH) {
            deauthClient();
        } else {
            struct pcap_pkthdr header;
            const unsigned char *packet = pcap_next(handler, &header);
            if (packet != nullptr) {
                try {
                    RadioTap radioTapPacket(packet, header.caplen);
                    processPacket(radioTapPacket);
                } catch (malformed_packet $e) {
                    //Not IEEE 802.11 packet
                }
            }
        }

        if (isDecrypted) {
            cout << "Captured " << capturedPacketsCount << " packets in " << (time(nullptr) - startTime)
                 << " seconds.\r";
            cout.flush();
        }
    }
}

void SnifferLibpcap::setFilter(string filter) {
    struct bpf_program pcapFilter{};

    if (pcap_compile(handler, &pcapFilter, filter.c_str(), 0, 0) == -1) {
        cerr << "Error: Could not compile filter: " << pcap_geterr(handler) << endl;
        exit(1);
    }

    //Set filter
    if (pcap_setfilter(handler, &pcapFilter) == -1) {
        cerr << "Error: Could not set filter: " << pcap_geterr(handler) << endl;
        exit(1);
    }
}


