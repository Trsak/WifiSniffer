/**
 * @file main.cpp
 * @author Petr Sopf (xsopfp00)
 * @brief Main program file, contains arguments parsing and program logic
 */

#include <iostream>
#include <string>
#include <unistd.h>
#include <csignal>
#include "sniffer.h"
#include "sniffer_libpcap.h"
#include "sniffer_libtins.h"

using namespace std;

//Global variables
string interfaceName; //Used interface name
string bssid; //BSSID of access point
string clientMac; //MAC address of client
string encryptionKey; //Encryption key
string saveFile; //Location of pcap file
bool onlyPassiveAttack = false; //Passive only attack
bool usingLibtins = false; //Use libtins or libpcap

/**
 * @return void
 *
 * Called upon program exit for cleaning up mess
 */
void exitSniffer() {
    cout << endl << "Exiting..." << endl;
}

/**
 * @return void
 *
 * Signal handler
 */
void signalHandler(int signum) {
    exit(signum);
}

/**
 * @return void
 *
 * Prints program help
 */
void printHelp(char *programName) {
    std::cout << "usage: " << programName
              << " [-h] -i INTERFACE_NAME -b BSSID -m CLIENT_MAC [-k ENCRYPTION_KEY] [-f SAVE_PCAP_FILE_LOCATION] [-p] [-l] [-t]"
              << std::endl;
    std::cout << std::endl;
    std::cout << "Required arguments:" << std::endl;
    std::cout << "  -i INTERFACE_NAME Network interface name." << std::endl;
    std::cout << "  -b BSSID Access point BSSID." << std::endl;
    std::cout << "  -m CLIENT_MAC Client mac address." << std::endl;
    std::cout << std::endl;
    std::cout << "Optional arguments:" << std::endl;
    std::cout << "  -h Prints this help." << std::endl;
    std::cout << "  -f SAVE_PCAP_FILE_LOCATION Location of pcap file containing captured packets." << std::endl;
    std::cout << "  -p Toggles passive attack only." << std::endl;
    std::cout << "  -l Use libpcap library for sniffing." << std::endl;
    std::cout << "  -t Use libtins library for sniffing." << std::endl;
}

int main(int argc, char **argv) {
    //Create exit handlers and capture SIGINT signal
    atexit(exitSniffer);
    signal(SIGINT, signalHandler);

    //Set default values
    interfaceName = "";
    bssid = "";
    clientMac = "";
    encryptionKey = "";
    saveFile = "./sniffing.pcap";

    //Parse program arguments
    int opt;
    while ((opt = getopt(argc, argv, "hplti:b:m:k:f:")) != -1) {
        switch (opt) {
            case 'h':
                printHelp(argv[0]);
                exit(0);
            case 'i':
                interfaceName = optarg;
                break;
            case 'b':
                bssid = optarg;
                break;
            case 'm':
                clientMac = optarg;
                break;
            case 'k':
                encryptionKey = optarg;
                break;
            case 'f':
                saveFile = optarg;
                break;
            case 'p':
                onlyPassiveAttack = true;
                break;
            case 'l':
                usingLibtins = false;
                break;
            case 't':
                usingLibtins = true;
                break;
            default:
                cerr << "Error: Unknown argument" << opt << "!" << endl;
                return 1;
        }
    }

    //Check required arguments
    if (interfaceName.empty()) {
        cerr << "Error: You have to specify interface name using -i parameter!" << endl;
        return 1;
    } else if (bssid.empty()) {
        cerr << "Error: You have to specify BSSID using -b parameter!" << endl;
        return 1;
    } else if (clientMac.empty()) {
        cerr << "Error: You have to specify client MAC address using -m parameter!" << endl;
        return 1;
    }

    //Initialize sniffer
    BasicSniffer *sniffer;
    if (usingLibtins) {
        cout << "Using libtins library for sniffing." << endl;
        sniffer = new SnifferLibtins(interfaceName, bssid, clientMac, encryptionKey, onlyPassiveAttack, saveFile);
    } else {
        cout << "Using libpcap library for sniffing." << endl;
        sniffer = new SnifferLibpcap(interfaceName, bssid, clientMac, encryptionKey, onlyPassiveAttack, saveFile);
    }

    //Start sniffing
    sniffer->startSniffing();
    return 0;
}