## NMap command cheat sheet

### General commands

* -sn: Disables port scan.
* -v: Enables the verbose output (include all hosts and ports in the output).
* -sV: Detects service versions.
* -A: Enables aggressive scan. The aggressive scan option supports OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (--traceroute). You should not use -A against target networks without permission.
* -p: Specifies the port to be scanned.
* -O: OS detection.

### ARP ping scan

```sh
nmap -sn -PR [Target IP Address/Range of IP addresses]
```

### UDP ping scan

A UDP response means that the host is active. If the target host is offline or unreachable, various error messages such as “host/network unreachable” or “TTL exceeded” could be returned.
```sh
nmap -sn -PU [Target IP Address/Range of IP addresses]
```

### ICMP ECHO ping scan

The ICMP ECHO ping scan involves sending ICMP ECHO requests to a host. If the target host is alive, it will return an ICMP ECHO reply. This scan is useful for locating active devices or determining if the ICMP is passing through a firewall.

```sh
nmap -sn -PE [Target IP Address/Range of IP addresses]
```

### Alternative to ICMP ECHO ping scan: ICMP Timestamp and Address Mask Ping Scan

#### ICMP timestamp ping scan
```sh
nmap -sn -PP [Target IP Address/Range of IP addresses]
```

#### ICMP address mask ping scan
```sh
nmap -sn -PM [Target IP Address/Range of IP addresses]
```

#### TCP ACK Ping Scan
This technique sends empty TCP ACK packets to the target host; an RST response means that the host is active.

```sh
nmap -sn -PA [Target IP Address/Range of IP addresses]
```

### IP Protocol Ping Scan
This technique sends different probe packets of different IP protocols to the target host, any response from any probe indicates that a host is active.
```sh
nmap -sn -PO [Target IP Address/Range of IP addresses]
```

### TCP connect/full open scan
```sh
nmap -sT -v [Target IP Address/Range of IP addresses]
```

### Stealth scan/TCP half-open scan
This scanning technique can be used to bypass firewall rules, logging mechanisms, and hide under network traffic.
```sh
nmap -sS -v [Target IP Address/Range of IP addresses]
```

### Xmas scan
Sends a TCP frame to a target system with FIN, URG, and PUSH flags set. If the target has opened the port, then you will receive no response from the target system. If the target has closed the port, then you will receive a target system reply with an RST.
```sh
nmap -sX -v [Target IP Address/Range of IP addresses]
```

### TCP Maimon scan
FIN/ACK probe is sent to the target; if there is no response, then the port is Open|Filtered, but if the RST packet is sent as a response, then the port is closed.
```sh
nmap -sM -v [Target IP Address/Range of IP addresses]
```

### ACK flag probe scan
Sends an ACK probe packet with a random sequence number; no response implies that the port is filtered (stateful firewall is present), and an RST response means that the port is not filtered.
```sh
nmap -sA -v [Target IP Address/Range of IP addresses]
```

### UDP scan
Uses UDP protocol instead of the TCP. There is no three-way handshake for the UDP scan. It sends UDP packets to the target host; no response means that the port is open. If the port is closed, an ICMP port unreachable message is received.
```sh
nmap -sU -v [Target IP Address/Range of IP addresses]
```

### IDLE/IPID Header Scan / Zombie Scan
A TCP port scan method that can be used to send a spoofed source address to a computer to discover what services are available.
```sh
nmap -sI -v [Target IP Address/Range of IP addresses]
```

Reference: https://nmap.org/book/idlescan.html

### SCTP COOKIE ECHO Scan
A COOKIE ECHO chunk is sent to the target host; no response implies that the port is open and ABORT Chunk response means that the port is closed.
```sh
nmap -sZ -v [Target IP Address/Range of IP addresses]
```

### Ping Sweep Scan
Discover the available hosts and their IP and MAC addresses, but no information about the ports.

```sh
nmap -sP [Target IP Address/Range of IP addresses]
```

### Display the open ports and services running 

```sh
nmap -T4 -A -v [Target IP Address/Range of IP addresses]
```
-T4: Specifies setting time template (0-5).
-A: Specifies setting ACK flag.

### smb-os-discovery
Attempts to determine the OS, computer name, domain, workgroup, and current time over the SMB protocol
```sh
nmap --script smb-os-discovery.nse [Target IP Address/Range of IP addresses]
```

### NetBIOS enumeration
```sh
nmap -sV -v --script nbstat.nse [Target IP Address/Range of IP addresses]
```

### Http enum - enumerate the applications, directories, and files in a web server
```sh
nmap -sV --script http-enum [Target IP Address/Range of IP addresses]
```

### hostmap-bfk
```sh
nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- [Target IP Address/Range of IP addresses]
```

### Http trace
Uses the TRACE method by sending an HTTP TRACE request that shows if the method is enabled or not
```sh
nmap --script http-trace -d [Target IP Address/Range of IP addresses]
```

### Http frontpage login
```sh
nmap [Target IP Address/Range of IP addresses] -p 80 --script = http-frontpage-login
```

### Http passwd
```sh
nmap --script http-passwd --script-args http-passwd.root =/ [Target IP Address/Range of IP addresses]
```

### Check whether Web Application Firewall is configured on the target host or domain
```sh
nmap -p80 --script http-waf-detect [Target IP Address/Range of IP addresses]
```

### Bypassing firewall/IDS

#### Fragment packets
Send fragmented probe packets to the intended target, which re-assembles it after receiving all the fragments.
```sh
nmap -f [Target IP Address/Range of IP addresses]
```

#### Source port manipulation
Manipulating actual port numbers with common port numbers to evade IDS/firewall (sometimes, firewall is configured to allow packets from well-known ports like HTTP, DNS, FTP, etc.).
```sh
nmap -g 80 [Target IP Address/Range of IP addresses]
```

#### Set number of Maximum Transmission Unit (MTU)
This technique evades the filtering and detection mechanism enabled in the target machine.
```sh
nmap -mtu 8 [Target IP Address/Range of IP addresses]
```

#### Decoy
Generating or manually specifying IP addresses of the decoys to evade IDS/firewall. Nmap automatically generates a random number of decoys for the scan and randomly positions the real IP address between the decoy IP addresses.

-D: performs a decoy scan.
RND: generates a random and non-reserved IP addresses.
```sh
nmap -D RND:10 [Target IP Address/Range of IP addresses]
```

#### Send the binary data as payload

```sh
nmap [Target IP Address/Range of IP addresses] --data 0xdeadbeef
```

#### Send string data as payload
```sh
nmap [Target IP Address/Range of IP addresses] --data-string "dummy string"
```

#### Append the number of random data bytes to most of the packets sent without any protocol-specific payloads

```sh
nmap --data-length 5 [Target IP Address/Range of IP addresses]
```

#### Scan in random order

```sh
nmap --randomize-hosts [Target IP Address/Range of IP addresses]
```

#### Send the packets with bad or bogus TCP/UPD checksums
```sh
nmap --badsum [Target IP Address/Range of IP addresses]
```

#### Send the packets with bad or bogus TCP/UPD checksums
```sh
nmap --badsum [Target IP Address/Range of IP addresses]
```



### Protection

#### Promiscuous detection
```sh
nmap --script=sniffer-detect [Target IP Address/Range of IP addresses]
```


[<- Back to index](README.md)

---
## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`