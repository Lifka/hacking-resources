## Steganography

### NTFS Streams

#### Hide file inside another file

```sh
type c:\calc.exe > c:\readme.txt:calc.exe
```
```sh
mklink executable_link.exe c:\readme.txt:calc.exe
executable_link.exe
```

### White Space Steganography using snow

#### Hide message in text file

```sh
snow -C -m "Secret message" -p "magic" readme.txt readme2.txt
```

#### Retrieve message from text file

```sh
snow -C -p "magic" readme2.txt
```

## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`