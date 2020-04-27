# Final Project for Codes and Ciphers: MATH-367
Mini-DES and DES project code for MATH-367

Created by: Andrew Chabot and John Shull

## Running the project

The main runnable code is the `miniDES.py` file.
* You are only required to have python3 and the `bitarray` package installed to run this code.
* The project includes code for running mini DES in verbose mode using a random key as well as a program for cracking the key used in the encryption given a binary plaintext and ciphertext.
* To run the verbose mini-DES mode, type `v` on input in the program. 
* To run the key crack code, type `c` for program input.
    * To run 100 key cracks and find statistics about the runtime, use `ce`
* To change text to encrypt, edit the `plain.txt` file

The `myDES.py` file can be run and outputs in a similar fashion to `miniDES`'s verbose mode, but has some issues and does not output the correct ciphertext that DES should do.

The `webImplementation.py` file is included mostly for reference, some code was borrowed from this file and this complete code is found at https://www.geeksforgeeks.org/data-encryption-standard-des-set-1/. This can be run from the command line and gives very verbose output for a DES run. It also can handle decryption in addition to encryption.
