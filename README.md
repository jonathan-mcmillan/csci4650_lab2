# csci4650_lab2

###Project Description

#####Overview
The goal of this project is to introduce you to the real-world applications of cryptography.It will involve the creation of a digital certificate as well as the use of both symmetric andasymmetric ciphers.

Your programs should validate invalgrindand be free of memory errors. Use of C orC++ is required, and the program must compile and run in the CS department labs. Your code should also be modularized and well-documented(commented).

#####
OPENSSL version on hopper.slu.edu: 
OpenSSL 1.0.2k-fips  26 Jan 2017
built on: reproducible build, date unspecified
platform: linux-x86_64
options:  bn(64,64) md2(int) rc4(16x,int) des(idx,cisc,16,int) idea(int) blowfish(idx)
compiler: gcc -I. -I.. -I../include  -fPIC -DOPENSSL_PIC -DZLIB -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DKRB5_MIT -m64 -DL_ENDIAN -Wall -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -Wa,--noexecstack -DPURIFY -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DRC4_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM
OPENSSLDIR: "/etc/pki/tls"
engines:  rdrand dynamic

Links for ducmentation:
http://www.linuxfromscratch.org/blfs/view/8.0/postlfs/openssl.html
https://www.openssl.org/docs/man1.0.2/man3/

######Part I
You will need to obtain a signed certificate from a certificate authority (e.g., CAcert) in thisstep. The CA will issue you a PKCS #12 key package, which will contain your public key,your private key, and the CA’s signature. If you do not want to obtain a certificate from a CA, you may also generate your own self-signed certificate. See the OpenSSL documentationor other online resources for details.

Then, you will need to use OpenSSL’s command-line utilities to extract the public andprivate keys and store them in the PEM format (e.g., aspubkey.pemandprivkey.pem).This is a Base-64 encoded format which you will be able to view in a standard text editor.

######Part II
Now, you must create a C or C++ program which is capable of using your public key, a thirdparty public key, and an encrypted session key to create a symmetric-key ciphertext and anasymmetric signature. Your plaintext file should include at least the names and Banner IDsof your group members; you may also include any other information as you see fit.

You are required to use DES mode for the symmetric cipher. The OpenSSL EVP librarywill be necessary for performing asymmetric (RSA) cryptography. It provides facilities forhashing, signing, encryption, etc.

Succinctly, your program must do the following:
1. Take the filenames of the plaintext message, the encrypted session key, the third-partypublic key, and your private key as command-line parameters.
2. Use the third-party public key to decrypt the session key.
3. Save the plaintext session key to a text file.
4. Use the DES session key to encrypt the plaintext.
5. Use your private key to sign the encrypted message.
6. Save the ciphertext and signature to an output file (or separate output files).

######Part III
Now, having created an encrypted and signed message, you must create another programwhich is capable of decrypting it and verifying the signature.

This program must take your public key, the plaintext session key, the ciphertext file,and the signature file (if it is separate) as parameters.  It should decrypt the ciphertextand print the result, as well as state whether or not the signature was determined to beauthentic.

Again, you should use DES, and use OpenSSL’s EVP library to perform RSA and sig-nature validation.

######Submission instructions
Submit a tarball (.taror.tgz) containing the following items:
•Your public key, in.pemformat.
•Your private key, in.pemformat.
•The signed ciphertext you produced.
•Your C or C++ files, with a Makefilewhich compiles them.
•A Readme which explains how to use your programs.

Make it clear which program is for Part II and which is for Part III; you may name themencryptionanddecryption, orpart2andpart3; any naming scheme is fine as long as itis clear which is used for which task.

Remember that your code must be modular, must be documented, must validate invalgrind’smemchecktool, and must compile and run successfully in the CS labs.

######Resources
•CAcert, a free certificate authority:
http://www.cacert.org/
•OpenSSL EVP manual:
https://www.openssl.org/docs/crypto/evp.html
•Valgrind Memcheck manual:
http://valgrind.org/docs/manual/mc-manual.html
