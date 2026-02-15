# Sniffer
A network packet sniffer created from scratch in c++ using raw sockets.

## Build

```
g++ sniffer.cpp -o sniffer
```

## Usage

```
sudo ./sniffer [OPTIONS]
```


For example:

Capture packets originating from interface ```wlan0``` and goting to port 678 of ip 34.107.221.82:

```
./snipher -f snipher.log --sif wlan0 --dport  678 --dip 34.107.221.82
```

You can use mulitple options for filtering while capturing packets with Snipher :

- **--tcp** : Capture only TCP packets
- **--udp** : Capture only UDP packets
- **--sip** : Filter packets by given source IP
- **--dip** : Filter packets by given destination IP
- **--sif** : Filter packets by source interface set as given interface. Matches source MAC of the packet against provided interface's MAC adress. Useful for filtering packets leaving from a given interface.
- **--dif** : Filter packets by destination interface set as given interface. Matches destination MAC of the packet against provided interface's MAC adress. Useful for filtering packets arriving at a given interface on the machine.
- **--sport** : Filter packets by source port
- **--dport** : Filter packets by destination port
- **--logfile** : Name of th log file for capturing packet data. Defaults to snipher_log.tx.

## What I Learned

- Raw Socket Programming
- Ethernet IP TCP/UDP headers
- Endian Handling
- Packet Filtering 

## References

- [Packet Sniffer Tutorial by eszotec](https://youtu.be/1Quv19IVFsc?si=rkuDLCqnQZerRRtZ) – Used for guidance and learning while building this project.

