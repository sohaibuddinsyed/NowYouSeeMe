# Now you see me : File encryption, decryption and transmission suite akin to SCP

This project implements a secure file transmission channel similar to SCP. The main components are described below:




### Key generation
A password is used to generate the encryption/decryption key using PBKDF2 (Password Based Key Derivation Function 2). Openssl provides PKCS5 PBKDF2 HMAC()
routine which uses PBKDF2 for generating a key. This is used in the project with
the digest EVP sha3 256() , 4096 iterations and ”SodiumChloride” as the salt. The
result is a 32 byte key. 

### Encryption
Encryption is done using AES256 in Galois Counter Mode (GCM) Mode. The EVP
interface in openssl provides methods that allows encryption using the key, IV and
tag as input.

### Decryption
The EVP interface in openssl also provides support for decryption.
### IV generation
The IV generation is a key step for ensuring credibility of AES while using GCM. A
12 byte cryptographically generated pseudorandom sequence returned by RAND bytes
is used as an IV in the project.

The outline of the usage of all the above happens in two modes.

## Local mode operation

In the local mode, a command line input of the type ```[ufsend input-file -l]``` is expected
for encryption and ```[ufrec filename -l]``` for decrytpion.

The encrytpion works as follows :
- A check on the validity of the command line arguments is performed.
- If successful, a password needs to be entered by the user and a corresponding
encryption key is generated.
- Next a 12 byte random IV is generated and along with the key is passed for
encryption.
- The tag generated for encryption, IV and the ciphertext are appended into the
input file in the same order.
e) The tag is passed to determine the authenticity of data during decryption.
f) A file with the same file name but ”.ufsec” appended is generated as the output
file.
- If the new file exists, main() exits with error code 33.
- The file has not been renamed as it was evident from the generic test provided
that the file will be manually removed.

The decryption works as follows:
- A check on the validity of the command line arguments is performed.
- If successful, a password needs to be entered by the user and a corresponding
decryption key is generated.
- Next the data from the input file is read. The first 16 bytes are for tag, the
next 12 bytes for IV and the rest is ciphertext.
- A file with the same file name minus ”.ufsec” is generated as the output file
with the plain text.
- If the new file exists, main() exits with error code 33.

## Network mode operation
The encryption works as follows :
- A check on the validity of the command line arguments of the client is performed. The input file name, ip address and ’-d’ flag are validated.
- If successful, a password needs to be entered by the user and a corresponding
encryption key is generated.
- A 12 byte random IV is generated and along with the key is passed for encryption.
- The client connects to the server ip using sockets.
- The tag generated for encryption, IV and the ciphertext are sent as three
buffers in the same order to the server.
- A reecipt of data is displayed.

The decryption works as follows:
- A check on the validity of the command line arguments of the client is performed.The input file name, ip address and ’-d’ flag are validated.
- If successful, the server binds to the port specified and listens for incoming
data.
- The dats=a is first dumped into the input file and then read. The first 16 bytes
are for tag, the next 12 bytes for IV and the rest is ciphertext.

- Next, a password needs to be entered by the user and a corresponding encryption key is generated.
- The tag, IV and the ciphertext are used for decryption. If either one is compromised, an error is displayed otherwise the ciphertext is.


## Running the program
The make utility must be used to create the program.
The file encryption programs ufsend and ufrec should take the following inputs:
``` bash
make
ufsend <input file> [-d < IP-addr:port >][-l]
ufrec <filename>  [-d < port >][-l] 
```
where ufsend takes an input file and transmits it to the IP address/port specified on the command-line (-d option), or dumps the encrypted contents of the input file.

Note: On each invocation, ufsend and ufrec  prompt the user for a password. 

## Results

### With password ”Hello”, printed the hexadecimal value of symmetric key derived by PBKDF2
![r1](https://user-images.githubusercontent.com/49821723/201233893-866be8d3-cede-48f5-b0c1-c7f8306b059f.png)

### Encrypted example.txt and displayed hexadecimal value of encrypted file
![r2](https://user-images.githubusercontent.com/49821723/201233965-b3a5659c-98d6-4118-b541-ee59efda545a.jpg)

### Sent encrypted file to ufrec and displayed receipt, hexadecimal value of encrypted file on screen
![r3](https://user-images.githubusercontent.com/49821723/201234183-32b9e5f7-4940-4dee-a7f8-aff1a871c367.jpg)

### Received file at ufrec, displayed hexadecimal value on screen
![r32](https://user-images.githubusercontent.com/49821723/201234295-270e2aad-6cde-4d4b-a65d-914e6ddfb58f.jpg)

### Decrypted file and displayed plaintext on screen
![r4](https://user-images.githubusercontent.com/49821723/201234361-e46682bc-9c32-4918-b101-cbeabe835e75.jpg)

### Locally encrypting a file
![send -l](https://user-images.githubusercontent.com/49821723/201234483-2ef3e4b4-2e6f-400f-8d02-0999d96be85c.png)

### Manually modifying ciphertext and decrypting
![failed -l](https://user-images.githubusercontent.com/49821723/201234624-66083aa6-9e87-43be-8dfd-7e7352899b8b.png)

### Exit code 33 when the file already exists
![r6](https://user-images.githubusercontent.com/49821723/201234682-fd9c0ced-fb90-4103-8b10-f3bb6c83ba37.jpg)




