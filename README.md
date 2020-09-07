# Wi-Fi Sniffer
This tool sniffs Wi-Fi data packets between selected client and access point. 
To sniff data, you have to know password or key used for encryption on given access point (in case of WEP, WPA-PSK and WPA2-PSK). Other encryptions are not supported.

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

## Example usage
For example, if we want to sniff communication between client with MAC adress `3C-3D-BD-60-FE-58` and access point with BSSID `F8-87-5F-A8-DD-26` that uses WPA2 encryption with key `y8THwDXNwRYH9kdU`. In this example, `wlp6s0` network interface is used for monitoring mode.
```
./sniffer -i wlp6s0 -m 3C-3D-BD-60-FE-58 -b F8-87-5F-A8-DD-26 -k y8THwDXNwRYH9kdU
```