/**
 * @file sniffer_libtins.cpp
 * @author Petr Sopf (xsopfp00)
 * @brief Implementation of libtins sniffer
 */
 
#include <iostream>
#include "sniffer_libtins.h"

using namespace std;
using std::runtime_error;

SnifferLibtins::SnifferLibtins(string interfaceNameA, string bssidA, string clientMacA,
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

void SnifferLibtins::startSniffing() {
    try {
        //Create sniffer config
        SnifferConfiguration config;
        config.set_rfmon(true); //Enable monitor mode
        config.set_snap_len(2048);  //Set the snapshot length to 2048
        config.set_promisc_mode(false);  //Turn off promiscuous mode
        config.set_timeout(512);  //Set the timeout to 512 milliseconds
        config.set_immediate_mode(true);  //Enable immediate mode
        config.set_filter(getFilter(true)); //Set sniffer filter

        //Create sniffer
        sniffer = new Sniffer(interfaceName, config);

        cout << "Interface " << interfaceName << " was set to monitor mode." << endl << endl;

        //Start sniffer loop
        SnifferStep lastStep = START_SNIFFING;
        while (true) {
            if (lastStep != currentStep) {
                getNewStepInfo(lastStep);
                lastStep = currentStep;
            }

            if (currentStep == CLIENT_DEAUTH) {
                deauthClient();
            } else {
                Packet packet = sniffer->next_packet();
                if (packet) {
                    processPacket(*packet.pdu());
                }
            }

            if (isDecrypted) {
                cout << "Captured " << capturedPacketsCount << " packets in " << (time(nullptr) - startTime)
                     << " seconds.\r";
                cout.flush();
            }
        }
    }
    catch (runtime_error &ex) {
        cerr << "Error: " << ex.what() << endl;
        exit(1);
    }
}

void SnifferLibtins::setFilter(string filter) {
    sniffer->set_filter(filter);
}
