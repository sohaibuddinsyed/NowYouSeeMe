#include<stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define IV_LENGTH 12
#define KEY_LENGTH 32
#define TAG_LENGTH 16

void printText(unsigned char *buf, int len) {
    for (int i = 0; i < len; i++)
        printf("%c", buf[i]);
    printf("\n");
}

void printHex(unsigned char *buf, int length) {
    for (int i = 0; i < length; i++)
        printf("%02X ", buf[i]);
    printf("\n");
}

int AES256Decryption(unsigned char *key, unsigned char *iv, unsigned char *tag, unsigned char *plaintext, unsigned char *ciphertext, int ciphertextLength) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintextLength, ret;

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) || 
    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL) ||
    !EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        printf("\nAES 256 initialization failed.");
        exit(1);
    }

    int decryptionResponse = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextLength);
    if(!decryptionResponse) {
        printf("\nAES 256 decryption failed.");
        exit(1);
    } else {
        plaintextLength = len;
    }
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintextLength += len;
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
        return plaintextLength;
    else return -1;
}

#define SIZE 1024
 
void write_file(int sockfd, char *filename) {
  int n;
  FILE *fp;
  char buffer[SIZE];
 
  fp = fopen(filename, "w");
  while (1) {
    n = recv(sockfd, buffer, SIZE, 0);
    if (n <= 0){
      break;
    }
    fwrite(buffer, sizeof(char), n, fp);
    bzero(buffer, SIZE);
  }
  fclose(fp);
  return;
}
int processFileInLocalMode(char *filename, FILE *fp, unsigned char *iv, unsigned char *tag, unsigned char **ciphertext) {
    fseek(fp, 0L, SEEK_END);
    int ciphertextLength = ftell(fp) - IV_LENGTH - 16; 
    fseek(fp, 0, SEEK_SET);    
    *ciphertext = (unsigned char*) malloc(ciphertextLength * sizeof(unsigned char));
    
    fread(iv, sizeof(char), IV_LENGTH, fp);
    fread(tag, 16, sizeof(char), fp);
    fread(*ciphertext, sizeof(char), ciphertextLength, fp);
    return ciphertextLength;
}
int receiveFileFromClient(int port, unsigned char *iv, unsigned char *tag, unsigned char **ciphertext, char *inputFile) {
    int server_fd, new_socket, valread;
	struct sockaddr_in address;
	int opt = 1, n;
	int addrlen = sizeof(address);

	// Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// Forcefully attaching socket to the port 8080
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

	// Forcefully attaching socket to the port 8080
	if (bind(server_fd, (struct sockaddr*)&address,sizeof(address))< 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_fd, 3) < 0) {
		exit(EXIT_FAILURE);
	}
    printf("Waiting for connections.\n");
	if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}
    printf("Inbound file.");
    write_file(new_socket, inputFile);
    char *successMessage = "Successfully received.";
    send(new_socket, successMessage, strlen(successMessage), 0);
    close(new_socket);
	shutdown(server_fd, SHUT_RDWR);

    FILE *fp;
    char *filename = inputFile;
    char buffer[SIZE];
 
    fp = fopen(filename, "r");

    fseek(fp, 0L, SEEK_END);
    int ciphertextLength = ftell(fp) - IV_LENGTH - 16; 
    fseek(fp, 0, SEEK_SET);    
    *ciphertext = (unsigned char*) malloc(ciphertextLength * sizeof(unsigned char));
    
    fread(iv, sizeof(char), IV_LENGTH, fp);
    fread(tag, 16, sizeof(char), fp);
    fread(*ciphertext, sizeof(char), ciphertextLength, fp);
	
    printHex(*ciphertext, ciphertextLength);
	return ciphertextLength;
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
    unsigned char key [KEY_LENGTH], password[50], *ciphertext, *plaintext, *tag, *iv;
    int ciphertextLength = 0;

    char filename[sizeof(argv[1])];
    char *inputFile = argv[1], *outputFile;

    FILE *fp;
    fp = fopen(inputFile, "r");

    if (fp == NULL)
    {
        printf("Cannot open file \n");
        exit(-1);
    }
    strcpy(filename, argv[1]);

    iv = (unsigned char*) malloc(IV_LENGTH * sizeof(unsigned char));
    tag = (unsigned char*) malloc(16 * sizeof(unsigned char));

    if(strcmp(modeOfOperation, "-d") == 0) {
        if(argc < 4) {
            printf("Insufficient arguments. ufrec <filename>  [-d < port >][-l]");
            exit(1);
        }
        int port = atoi(argv[3]);
        ciphertextLength = receiveFileFromClient(port, iv, tag, &ciphertext, inputFile);
    }

    printf("Password: ");
    scanf("%s", password); 

    PKCS5_PBKDF2_HMAC(password, -1, "SodiumChloride", 14, 4096, EVP_sha3_256(), KEY_LENGTH, key);
    
    printf("Key: ");
    printHex(key, KEY_LENGTH);

    if(strcmp(modeOfOperation, "-l") == 0) {
        ciphertextLength = processFileInLocalMode(inputFile, fp, iv, tag, &ciphertext);
        plaintext = (unsigned char*) malloc(ciphertextLength * sizeof(unsigned char));
        int sizept = AES256Decryption(key, iv, tag, plaintext, ciphertext, ciphertextLength);
        if(sizept <= 0) {
            printf("Decryption failed. Incorrect password and/or ciphertext/iv/tag have been compromised.\n");
            exit(1);
        }
        printHex(ciphertext, ciphertextLength);
        int i = 0;
        outputFile = (char*) malloc((strlen(inputFile) - 6) * sizeof(char));
        while(i < (strlen(inputFile) - 6)) {
            outputFile[i] = inputFile[i];
            i++;
        }
        outputFile[i] = '\0';
        if (access(outputFile, F_OK) == 0) {
            printf("%s already exists. Returning 33 from main() and aborting.\n", outputFile);
            return 33;
        }
        fp = freopen(outputFile, "w", fp);
        fwrite(plaintext, sizeof(char), sizept, fp);
        printf("Successfully decrypted %s to %s (%d bytes written).\n", inputFile, outputFile, sizept * 8);
        printText(plaintext, sizept);
    } else {
        plaintext = (unsigned char*) malloc(ciphertextLength * sizeof(unsigned char));
        int sizept = AES256Decryption(key, iv, tag, plaintext, ciphertext, ciphertextLength);
        if(sizept <= 0) {
            printf("Decryption failed. Incorrect password and/or ciphertext/iv/tag have been compromised.\n");
            exit(1);
        }
        printHex(ciphertext, ciphertextLength);
        fp = freopen(inputFile, "w", fp);
        fwrite(plaintext, sizeof(char), sizept, fp);
        printf("Successfully received and decrypted %s (%d bytes written).\n", inputFile, sizept * 8);
        printText(plaintext, sizept);
    }
    fclose(fp);
    return 0;
}

