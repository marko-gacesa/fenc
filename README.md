# fenc

`fenc` is a tool for encrypting and decrypting files.

It will GZip input files and encode them with the provided password. Input files will be removed unless the option `-k` is provided.

Usage:

> fenc input.txt

Produces the file `input.txt.fenc` and removes the `input.txt`. 

> fenc input.txt.fenc

Restores original the original `input.txt` and removes the encrypted `input.txt.fenc`.