## Steganography

### White Space Steganography using snow

#### Hide message in text file

```sh
snow -C -m "Secret message" -p "magic" readme.txt readme2.txt
```

#### Retrieve message from text file

```sh
snow -C -p "magic" readme2.txt
```

