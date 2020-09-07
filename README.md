# Wi-Fi Sniffer
This tool sniffs Wi-Fi data packets between selected client and access point. 
To sniff data, you have to know password or key used for encryption on given access point (in case of WEP, WPA-PSK and WPA2-PSK). Other encryptions are not supported.

## Program flow
1. Start sniffing by setting network interface to use monitor mode and filter Wi-Fi packets.
1. Collect beacon frame and detect used encryption.
1. If WPA or WPA 2 is used, try to deauthenticate client and wait for 4-way auth handshake. If only passive mode is toggled, then program just waits for 4-way auth handshake.
1. Start sniffing data packets and save them to output file.

## Requirements
Installing Libpcap and Libtins libraries is required:
```
sudo apt-get install libpcap-dev libtins-dev
```

Network adapter with monitor mode support is also required.

## Compile and run
To compile program:
```
mkdir build
cd build
cmake ..
make
```

To run program and display help:
```
./sniffer -h
```

## Usage example
For example, if we want to sniff communication between client with MAC adress `3C-3D-BD-60-FE-58` and access point with BSSID `F8-87-5F-A8-DD-26` that uses WPA2 encryption with key `y8THwDXNwRYH9kdU`. In this example, `wlp6s0` network interface is used for monitoring mode.
```
./sniffer -i wlp6s0 -m 3C-3D-BD-60-FE-58 -b F8-87-5F-A8-DD-26 -k y8THwDXNwRYH9kdU
```

## Program arguments
### Required

* `-i INTERFACE_NAME` - Network interface name.
* `-m BSSID` - Access point BSSID.
* `-b CLIENT_MAC` - Client MAC address.

### Optional

* `-h` - Prints program help.
* `-k ENCRYPTION_KEY` - Encryption key.
* `-f SAVE_PCAP_FILE_LOCATION` - Location of the output pcap file containing captured packets.
* `-p` - Toggles passive attack only.
* `-l` - Toggles libpcap library for sniffing.
* `-t` - Toggles libtins library for sniffing.

## Output
Program saves all captured and decrypted data packets in `.pcap` file.
