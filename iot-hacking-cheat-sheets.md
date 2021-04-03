## Internet of Things (IoT) hacking cheat sheet

### Gathering using Shodan

#### Search for webcams using geolocation

```sh
webcamxp country:"ES"
```

#### Search for webcams using city

```sh
webcamxp city:"Barcelona"
```

#### Search for webcams using longitude and latitude

```sh
webcamxp geo:"41.3964, 2.1793"
```

#### Search for Modbus-enabled ICS/SCADA systems

```sh
port:502
```

#### Search for SCADA systems using PLC name

```sh
“Schneider Electric”
```

#### Search for SCADA systems using geolocation

```sh
SCADA Country:"US"
```




[<- Back to index](README.md)

---
## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`