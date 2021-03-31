## Hacking web cheat sheet

### Gathering web server

#### Finding default content of web server using nikto

```sh
nikto -h [HOST] -Tuning x
```

#### Analyze website using skipfish

```sh
skipfish -o /root/output -S /usr/share/skipfish/dictionaries/complete.wl [HOST:8080]
```

#### Discover web directories using uniscan

```sh
uniscan -u [HOST] -q
```

#### Discover robots.txt and sitemap.xml files using uniscan
```sh
uniscan -u [HOST] -we
```

#### Perform dynamic tests using uniscan
Obtains information about emails, source code disclosures, and external hosts.

```sh
uniscan -u [HOST] -d
```

#### Enamerate server using nmap
[nmap-cheat-sheet.md](nmap-cheat-sheet.md)

## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`