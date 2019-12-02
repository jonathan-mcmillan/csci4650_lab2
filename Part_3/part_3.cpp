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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

using namespace std;

string readFile(string fileName);
//Takes a string fileName indicating the location of a file to be read and returns a string of the contents

int main(int argc, char *argv[]) {
    	//start of 1
	string publicKeyFN, plaintextSessionKeyFN, ciphertextMessageFN;
    	if(argc != 4) {
        	cout << "Usage: part_3 <public_key.pem> <plaintext_session_key.txt> <ciphertext.txt>" << endl << "Incorrect number of parameters entered -- using default file name values instead." << endl;
        
		publicKeyFN = "jon_public.pem";
            	plaintextSessionKeyFN = "decrypted_session.txt";
            	ciphertextMessageFN = "ciphertext.txt";
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
