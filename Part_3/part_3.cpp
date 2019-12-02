// Oliver Grassmann & Jonathan McMillan
// 19 Nov 2019
// CSCI 4650 - Computer Security
// Programming Assignment 2 - Part 2

/*
Now, having created an encrypted and signed message, you must create another program which is capable of decrypting it and verifying the signature.
This program must take your public key, the plaintext session key, the ciphertext file, and the signature file (if it is separate) as parameters. It should decrypt the ciphertext and print the result, as well as state whether or not the signature was determined to be authentic.
Again, you should use DES, and use OpenSSL’s EVP library to perform RSA and sig- nature validation.
*/

#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include <cerrno>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/des.h>
#include <openssl/conf.h>
#include <openssl/err.h>

using namespace std;

string readFile(string fileName);
//Takes a string fileName indicating the location of a file to be read and returns a string of the contents
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
//Decrypts a ciphertext buffer using DES
//
void handleErrors(void);
//Prints errors to stdout

int main(int argc, char *argv[]) {
    	//start of 1
	string publicKeyFN, plaintextSessionKeyFN, ciphertextMessageFN;
    	if(argc != 4) {
        	cout << "Usage: part_3 <public_key.pem> <plaintext_session_key.txt> <ciphertext.txt>" << endl << "Incorrect number of parameters entered -- using default file name values instead." << endl;
        
		publicKeyFN = "jon_public.pem";
            	plaintextSessionKeyFN = "decrypted_session.txt";
            	ciphertextMessageFN = "cipher_text.txt";
    	} else {
        	publicKeyFN = argv[1];
            	plaintextSessionKeyFN = argv[2];
            	ciphertextMessageFN = argv[3];
    	}

    	string publicKey = readFile(publicKeyFN);
    	cout << "Public Key: " << endl << publicKey << endl;

    	string plaintextSessionKey = readFile(plaintextSessionKeyFN);
    	cout << "Plaintext Session Key: " << endl << plaintextSessionKey << endl; 

    	string ciphertextMessage = readFile(ciphertextMessageFN);
    	cout << "Ciphertext Message: " << endl << ciphertextMessage << endl;

	//---Verify Signature---

	//---Decrypt Ciphertext---
	cout << "Start decryption" <<endl;
	ERR_load_crypto_strings();
	size_t outlen, inlen;
	unsigned char *iv = (unsigned char *) "0123456789012345";
	unsigned char decryptedText[outlen];
	unsigned char *out, *in;
	int decryptedText_len;
	cout << "before decrypt call" << endl;
	decryptedText_len = decrypt((unsigned char *) ciphertextMessage.c_str(), strlen((char *) ciphertextMessage.c_str()), (unsigned char *) plaintextSessionKey.c_str(), iv, decryptedText);
	if(decryptedText_len <= 0){
		throw(errno);
	}
	cout << "after decrypt call" << endl;

	return 0;
}

string readFile(string fileName) {
        //file reading https://insanecoding.blogspot.com/2011/11/how-to-read-in-file-in-c.html
	const char *filename = fileName.c_str();
        FILE *file = fopen(filename, "rb");
        
	if(file){
        	string contents;
                fseek(file, 0, SEEK_END);
                contents.resize(ftell(file));
                rewind(file);
                fread(&contents[0], 1, contents.size(), file);
                fclose(file);
        	return(contents);
        }
        throw(errno);
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
    * Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stdout);
    abort();
}
