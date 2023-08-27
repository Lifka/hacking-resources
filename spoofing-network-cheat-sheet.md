## Spoofing networks cheat sheet

### MAC Flooding
Involves flooding the CAM table with fake MAC address and IP pairs until it is full.

#### Using macof

```sh
macof -i eth0 -n 100
```
-i: Specifies the interface and -n: specifies the number of packets to be sent.

### DNS Poisoning
Involves tricking a DNS server into believing that it has received authentic information when, in reality, it has not.

### ARP Poisoning
Involves constructing a large number of forged ARP request and reply packets to overload a switch. ARP spoofing succeeds by changing the IP address of the attacker’s computer to the IP address of the target computer. A forged ARP request and reply packet find a place in the target ARP cache in this process. As the ARP reply has been forged, the destination computer (target) sends the frames to the attacker’s computer, where the attacker can modify them before sending them to the source machine (User A) in an MITM attack.

#### Using arpspoof 
arpspoof redirects packets from a target host (or all hosts) on the LAN intended for another host on the LAN by forging ARP replies. This is an extremely effective way of sniffing traffic on a switch.

```sh
 arpspoof -i eth0 -t [IP Adress Range]
```
-i: Specifies network interface.

-t: Specifies target IP address.

-r: IP to spoof.

### DHCP Attacks
Involves performing a DHCP starvation attack and a rogue DHCP server attack. In a DHCP starvation attack, an attacker floods the DHCP server by sending a large number of DHCP requests and uses all available IP addresses that the DHCP server can issue. As a result, the server cannot issue any more IP addresses, leading to a Denial-of-Service (DoS) attack. Because of this issue, valid users cannot obtain or renew their IP addresses, and thus fail to access their network. This attack can be performed by using various tools such as Yersinia and Hyenae.

#### DHCP Starvation Attack using Yersinia

```sh
yersinia -I
```
-I: Starts an interactive ncurses session.


```sh
[Press F2]
```
F2: Sets DHCP mode.


```sh
[Press x]
[Press 1]
```
x: List available attack options.

1: Start a DHCP starvation attack.

[<- Back to index](README.md)

---
## License

© 2023 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`