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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
//Encrypts a plaintext buffer in a buffer using DES

void handleErrors(void);
//Prints errors to stdout

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
	//https://www.openssl.org/docs/man1.0.2/man3/EVP_PKEY_encrypt.html

	ENGINE *eng = ENGINE_get_default_RSA();	
	unsigned char *out, *in;
	size_t outlen, inlen; 
	
	//read public key 
	cout << "pub key" << endl;
	FILE *pub = fopen(thirdPartyPublicKeyFN.c_str(), "rb");
	EVP_PKEY *pub_key = PEM_read_PUBKEY(pub, NULL, NULL, NULL);
	if(pub_key == NULL){
		throw(errno);
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, eng);
	if(!ctx){
		throw(errno);
	}

	if(EVP_PKEY_encrypt_init(ctx) <= 0){
		throw(errno);
	}

	if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){
		throw(errno);
	}
	
	in =(unsigned char *) encryptedSessionKey.c_str();
    inlen = strlen(encryptedSessionKey.c_str());
	
	if(EVP_PKEY_encrypt_init(ctx) <= 0){
		throw(errno);
	}

	//find buffer length
	if(EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0){
		throw(errno);
	}

	out = (unsigned char*) OPENSSL_malloc(outlen);

	if(!out){
		throw(errno);
	}
	 
	if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0){
		//throw(errno);
        cout << "unable to decrypt session key..." << endl << &out << endl << out << endl;
	}
	//at this point decrypted data is in buffer -- assume this is right for now
	//end of 2
	
	string de_ses((char *) out);
	cout << hex << de_ses << endl;

	//start of 3
	//write buffer to a file
	//http://www.cplusplus.com/reference/cstdio/fwrite/
	ofstream out_f("decrypted_session.txt");
	out_f << de_ses;
	out_f.close();

	// 4. Use DES session key to encrypt the plaintext
	unsigned char *iv = (unsigned char *) "0123456789012345";
	unsigned char ciphertext[outlen];
	int ciphertext_len;

	ciphertext_len = encrypt((unsigned char *) plaintextMessage.c_str(), strlen ((char *) plaintextMessage.c_str()), out, iv, ciphertext);
	if(ciphertext_len <= 0){
		throw(errno);
	}

	cout << "Ciphertext Length: " << ciphertext_len << endl;
	cout << "Ciphertext: " << endl << ciphertext << endl;



	return 0;
}

//https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stdout);
    abort();
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
