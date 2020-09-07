/**
 * @file sniffer.cpp
 * @author Petr Sopf (xsopfp00)
 * @brief Implementation of BasicSniffer methods
 */

#include "sniffer.h"

string BasicSniffer::getFilter(bool includeBroadcast) {
    if (includeBroadcast) { //Should filter include broadcasts?
        return "wlan addr3 " + bssid + " and (wlan addr1 " + clientMac + " or wlan addr2 " + clientMac +
               " or wlan addr1 ff:ff:ff:ff:ff:ff)";
    }

    return "wlan addr3 " + bssid + " and (wlan addr1 " + clientMac + " or wlan addr2 " + clientMac + ")";
}

void BasicSniffer::getNewStepInfo(BasicSniffer::SnifferStep lastStep) {
    switch (lastStep) {
        case START_SNIFFING: //Just started sniffing, collect beacon frame
            cout << endl << "Collecting beacon frame to gather info..." << endl;
            break;
        case CAPTURE_BEACON: //Collected data, next step depends on used encryption
            setFilter(getFilter(false));
            startTime = time(nullptr);

            switch (encryption) {
                case RSNInformation::WEP_40:
                case RSNInformation::WEP_104:
                    decrypter.add_password(bssid, encryptionKey);
                    cout << endl << "Collecting data and decrypting them with WEP..."
                         << endl;
                    currentStep = DECRYPT_WEP;
                    break;
                case RSNInformation::TKIP:
                case RSNInformation::CCMP:
                    wpa2Decrypter.add_ap_data(encryptionKey, ssid, bssid);
                    cout << endl << "We have to collect 4-way auth handshake..."
                         << endl;
                    currentStep = CLIENT_DEAUTH;
                    break;
                default:
                    cout << endl << "[Collecting packets]" << endl;
                    currentStep = SNIFF_NO_ENCRYPTION;
                    break;
            }
            break;
        default:
            cout << endl;
            break;
    }
}

bool BasicSniffer::processPacket(PDU &pdu) {
    switch (currentStep) {
        case CAPTURE_BEACON: //We need to collect beacon frame
            collectBeacon(pdu);
            break;
        case DECRYPT_WEP: //Decrypt WEP data frames
            collectDataWEP(pdu);
            break;
        case DECRYPT_WPA: //Decrypt WPA data frames
            collectDataWPA(pdu);
            break;
        case SNIFF_NO_ENCRYPTION: //No encryption used, just save data
            collectData(pdu);
            break;
        default:
            break;
    }

    return true;
}

void BasicSniffer::collectBeacon(PDU &pdu) {
    try {
        //Try to parse beacon frame
        const Dot11Beacon &beacon = pdu.rfind_pdu<Dot11Beacon>();

        //Beacon must be broadcast
        if (!beacon.from_ds() && !beacon.to_ds()) {
            wpa2Decrypter.decrypt(pdu);
            cout << "Found beacon frame!" << endl;

            //Collect SSID
            ssid = beacon.ssid();
            cout << "SSID: " << ssid << endl;

            //Collect channel
            apChannel = beacon.ds_parameter_set();
            cout << "Channel: " << apChannel << endl;

            //Check privacy tag
            bool isPrivacy = beacon.capabilities().privacy();
            if (isPrivacy) {
                cout << "AP is using some sort of encryption, trying to detect..." << endl;
                string encryptionText = "WEP";
                encryption = RSNInformation::WEP_40;

                try { //Try to find RSN and detect encryption
                    RSNInformation rsnInformation = beacon.rsn_information();
                    RSNInformation::CypherSuites groupSuite = rsnInformation.group_suite();
                    encryption = groupSuite;

                    switch (groupSuite) {
                        case RSNInformation::WEP_40:
                            encryptionText = "WEP_40";
                            break;
                        case RSNInformation::TKIP:
                            encryptionText = "TKIP";
                            break;
                        case RSNInformation::CCMP:
                            encryptionText = "CCMP";
                            break;
                        case RSNInformation::WEP_104:
                            encryptionText = "WEP_104";
                            break;
                        case RSNInformation::BIP_CMAC_128:
                            encryptionText = "BIP_CMAC_128";
                            break;
                        case RSNInformation::GCMP_128:
                            encryptionText = "GCMP_128";
                            break;
                        case RSNInformation::GCMP_256:
                            encryptionText = "GCMP_256";
                            break;
                        case RSNInformation::CCMP_256:
                            encryptionText = "CCMP_256";
                            break;
                        case RSNInformation::BIP_GMAC_128:
                            encryptionText = "BIP_GMAC_128";
                            break;
                        case RSNInformation::BIP_GMAC_256:
                            encryptionText = "BIP_GMAC_256";
                            break;
                        case RSNInformation::BIP_CMAC_256:
                            encryptionText = "BIP_CMAC_256";
                            break;
                    }
                } catch (option_not_found &ex) {
                    try { //RSN not found, try to detect WPA
                        auto vendorSpecificOui = beacon.vendor_specific().oui;

                        if (vendorSpecificOui == "00:50:f2") { //WPA vendor, detect specific encryption
                            auto data = beacon.vendor_specific().data;
                            if (data.size() > 7) {
                                if (data[6] == 0x02) {
                                    encryption = RSNInformation::TKIP;
                                    encryptionText = "TKIP";
                                } else if (data[6] == 0x01) {
                                    encryption = RSNInformation::WEP_40;
                                    encryptionText = "WEP_40";
                                } else if (data[6] == 0x04) {
                                    encryption = RSNInformation::CCMP;
                                    encryptionText = "CCMP";
                                } else if (data[6] == 0x05) {
                                    encryption = RSNInformation::WEP_104;
                                    encryptionText = "WEP_104";
                                }
                            } else {
                                encryption = RSNInformation::WEP_40;
                            }
                        }
                    } catch (option_not_found &ex) {
                        encryption = RSNInformation::WEP_40;
                    }
                }

                cout << "Detected encryption: " << encryptionText << endl;
            } else {
                cout << "AP is not using any encryption!" << endl;
            }

            currentStep = DECRYPT_START;
        }
    } catch (pdu_not_found &ex) {
        //Given frame is not beacon
    }
}

void BasicSniffer::collectData(PDU &pdu) {
    if (!isDecrypted) {
        startTime = time(nullptr);
        isDecrypted = true;
    }

    ++capturedPacketsCount;
    packetWriter->write(pdu);
}

void BasicSniffer::collectDataWEP(PDU &pdu) {
    if (encryptionKey.empty()) {
        cerr << "Error: You have to specify WEP encryption key using -k!" << endl;
        exit(1);
    }

    if (decrypter.decrypt(pdu)) {
        if (!isDecrypted) {
            startTime = time(nullptr);
            cout << "Managed to decrypt packet data!" << endl;
            isDecrypted = true;
        }

        ++capturedPacketsCount;
        packetWriter->write(pdu);
    }
}

void BasicSniffer::collectDataWPA(PDU &pdu) {
    if (encryptionKey.empty()) {
        cerr << "Error: You have to specify WPA PSK key using -k!" << endl;
        exit(1);
    }

    if (wpa2Decrypter.decrypt(pdu)) {
        if (!isDecrypted) {
            startTime = time(nullptr);
            cout << "Managed to decrypt packet data!" << endl;
            isDecrypted = true;
        }

        ++capturedPacketsCount;
        packetWriter->write(pdu);
    }
}

void BasicSniffer::deauthClient() {
    if (shouldAttackOnlyPassive) {
        cout << "Only passive attack is enabled, waiting for client authentication." << endl;
    } else {
        cout << "Building deauthentication packets..." << endl;

        NetworkInterface networkInterface = NetworkInterface(interfaceName);

        //Construct and send 10 deauth frames
        for (int i = 0; i < 10; i++) {
            cout << "Sending deauthentication packet (" << (i + 1) << "/10).\r";
            cout.flush();

            RadioTap radio = RadioTap();
            Dot11Deauthentication deauthentication = Tins::Dot11Deauthentication();
            PacketSender sender;

            radio.channel(Utils::channel_to_mhz(apChannel), apChannel);
            deauthentication.addr1(bssid);
            deauthentication.addr2(clientMac);
            deauthentication.addr3(bssid);
            radio.inner_pdu(deauthentication);
            sender.send(radio, networkInterface);
        }

        cout << endl << "All deauthentication packets sent!" << endl;
        cout << endl << "Capturing 4-way auth handshake..." << endl;
    }

    currentStep = DECRYPT_WPA;
}
