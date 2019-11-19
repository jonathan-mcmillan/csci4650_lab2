// Oliver Grassmann & Jonathan McMillan
// 1 Nov 2019
// CSCI 4650 - Computer Security
// Programming Assignment 2 - Part 2

/*
1. Take the ﬁlenames of the plaintext message, the encrypted session key, the third-party public key, and your private key as command-line parameters. 
2. Use the third-party public key to decrypt the session key. 
3. Save the plaintext session key to a text ﬁle. 
4. Use the DES session key to encrypt the plaintext. 
5. Use your private key to sign the encrypted message. 6. Save the ciphertext and signature to an output ﬁle (or separate output ﬁles).
*/

#include <iostream>
#include <string>
#include <cstdio>
#include <cerrno>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

string readFile(string fileName);
//Takes a string fileName indicating the location of a file to be read and returns a string of the contents


int main(int argc, char *argv[]) {
    	//start of 1
	string plaintextMessageFN, encryptedSessionKeyFN, thirdPartyPublicKeyFN, yourPrivateKeyFN;
    	if(argc != 5) {
        	cout << "Usage: part2 <plaintext_message.txt> <encrypted_session.key> <third-party_public_key.pem> <your_private_key.pem>" << endl << "Incorrect number of parameters entered, using default file name values instead." << endl;
        
        	plaintextMessageFN = "plaintext_message.txt";
        	encryptedSessionKeyFN = "encrypted_session.key";
        	thirdPartyPublicKeyFN = "pubkey.pem";
        	yourPrivateKeyFN = "oliver_privkey.pem";
    	} else {
        	plaintextMessageFN = argv[1];
        	encryptedSessionKeyFN = argv[2];
        	thirdPartyPublicKeyFN = argv[3];
        	yourPrivateKeyFN = argv[4];
    	}

    string plaintextMessage = readFile(plaintextMessageFN);
    cout << "Plaintext Message: " << endl << plaintextMessage << endl;

    string encryptedSessionKey = readFile(encryptedSessionKeyFN);
    cout << "Encrypted Session Key: " << endl << encryptedSessionKey << endl; 

    string thirdPartyPublicKey = readFile(thirdPartyPublicKeyFN);
    cout << "Third-Party Public Key: " << endl << thirdPartyPublicKey << endl;

    string yourPrivateKey = readFile(yourPrivateKeyFN);
    cout << "Your Private Key: " << endl << yourPrivateKey << endl;

	//start of 2 - https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope
	//there is a section called opening and envelope which should help with this
	
	//read public key 
	cout << "pub key" << endl;
	FILE *pub = fopen(thirdPartyPublicKeyFN.c_str(), "rb");
	EVP_PKEY *pub_key = PEM_read_PUBKEY(pub, NULL, NULL, NULL);
	if(pub_key == NULL){
		throw(errno);
	}

	//read private key
	cout << "priv key" << endl;
	FILE *priv = fopen(yourPrivateKeyFN.c_str(), "rb");
	EVP_PKEY *priv_key = PEM_read_PrivateKey(priv, NULL, NULL, NULL);
	if(priv_key == NULL){
		throw(errno);
	}

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
