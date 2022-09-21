#include<stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define IV_LENGTH 12
#define KEY_LENGTH 32
#define TAG_LENGTH 16

void RAND_bytes(char * iv, int byteSize);

void printHex(unsigned char *buf, int length) {
    for (int i = 0; i < length; i++)
        printf("%02X ", buf[i]);
    printf("\n");
}

int AES256Encryption(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag, unsigned char *plaintext, int plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int cipherTextLength, length;

    // Initializing the encryption
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) || 
    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL) ||
    !EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        printf("\nAES 256 initialization failed.");
        exit(1);
    }

    // Performing encryption
    int encryptionResponse = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_len);
    if(!encryptionResponse) {
        printf("\nAES 256 encryption failed.");
        exit(1);
    } else {
        cipherTextLength = length;
    }
    
    // Finalizing encryption and setting up the tag
    EVP_EncryptFinal_ex(ctx, ciphertext + length, &length);
    cipherTextLength += length;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, tag);
    EVP_CIPHER_CTX_free(ctx);      
    return cipherTextLength;
}

void cd t   sendFileToDaemon(char **argv, char *iv, char *ct, char *tag, int sizeCT,  int plainTextLength, char *inputFile, char *outputFile) {
    char destinationAddress[20];
    strcpy(destinationAddress, argv[3]);
    char *ipAndPort = argv[3], *ip = strtok(ipAndPort, ":"), buffer[1024];
    int port = atoi(strtok(NULL, ":"));
    
    int sock = 0, valread, client_fd;
	struct sockaddr_in serv_addr;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		exit(1);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, ip, &serv_addr.sin_addr)<= 0) {
		printf("\nInvalid address or Address not supported \n");
		exit(1);
	}

	if ((client_fd = connect(sock, (struct sockaddr*)&serv_addr,sizeof(serv_addr)))< 0) { 
		printf("\nConnection Failed \n");
		exit(1);
	}
    printf("Connected to server\n");
    send(sock, iv, IV_LENGTH, 0);
    send(sock, tag, TAG_LENGTH, 0);
	send(sock, ct, sizeCT, 0);
    printf("Successfully encrypted %s to %s (%d bytes written).\n", inputFile, outputFile, plainTextLength * 8);
    printHex(ct, plainTextLength);
    printf("Transmitting to %s.\nReceived file.\n", destinationAddress);
	close(client_fd);
}

void processFileInLocalMode(FILE *fp, char *ct, int sizeCT, char *iv, char *tag, int plainTextLength, char *inputFile, char *outputFile) {
    fwrite(iv, sizeof(char), IV_LENGTH, fp);
    fwrite(tag, sizeof(char), TAG_LENGTH, fp);
    fwrite(ct, sizeof(char), sizeCT, fp);

    printf("Successfully encrypted %s to %s (%d bytes written).\n", inputFile, outputFile, plainTextLength * 8);
    printHex(ct, plainTextLength);
}

int main(int argc, char **argv) {
    
    if(argc < 3) {
        printf("Insufficient arguments. \nRequired : ufsend <input file> [-d < IP-addr:port >][-l] or \n ufrec <filename>  [-d < port >][-l].\n");
        exit(1);
    } 
    char *modeOfOperation = argv[2];
    if(!strcmp(modeOfOperation, "-l") == 0 && !strcmp(modeOfOperation, "-d") == 0) {
        printf("Invalid flag. Use '-l' or '-d'.\n");
        exit(1);
    }

    unsigned char key[KEY_LENGTH], password[500], *cipherText, tag[TAG_LENGTH], *plaintext, *iv;
    char outputFileName[strlen(argv[1])], *inputFile = argv[1];
    strcpy(outputFileName, argv[1]);
    
    printf("Password: ");
    scanf("%s", password);

    iv = (unsigned char*) malloc(IV_LENGTH * sizeof(unsigned char));
    RAND_bytes(iv, IV_LENGTH); 

    FILE *fp;
    fp = fopen(inputFile, "r");
    if (fp == NULL) {
        printf("\nCannot open file %s\n", inputFile);
        exit(-1);
    }
    
    fseek(fp, 0L, SEEK_END);
    int plainTextLength = ftell(fp) ; 
    fseek(fp, 0, SEEK_SET);

    plaintext = (unsigned char*) malloc(plainTextLength * sizeof(unsigned char));
    fread(plaintext, sizeof(char), plainTextLength, fp);

    PKCS5_PBKDF2_HMAC(password, -1, "SodiumChloride", 14, 4096, EVP_sha3_256(), KEY_LENGTH, key);
    
    printf("Key: ");
    printHex(key, KEY_LENGTH);

    cipherText = (unsigned char*) malloc(plainTextLength * sizeof(unsigned char));
    int sizeCipherText = AES256Encryption(key, iv, cipherText, tag, plaintext, plainTextLength);
        
    if(strcmp(modeOfOperation, "-l") == 0) {
        strcat(outputFileName, ".ufsec");
        if (access(outputFileName, F_OK) == 0) {
            printf("%s already exists. Returning 33 from main() and aborting.\n", outputFileName);
            return 33;
        }
        fp = freopen(outputFileName, "w", fp);
        processFileInLocalMode(fp, cipherText, sizeCipherText, iv, tag, plainTextLength, inputFile, outputFileName);
    } else if(strcmp(modeOfOperation, "-d") == 0) {
        sendFileToDaemon(argv, iv, cipherText, tag, sizeCipherText, plainTextLength, inputFile, outputFileName);
    } 
    fclose(fp);
    return 0;
}
