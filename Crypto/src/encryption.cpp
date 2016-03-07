/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <iostream>
#include <string.h>
#include <fstream>
#include <string>
#include "encryption.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "aes.h"
#include <cstdlib> 
#include <ctime>
#include <string.h>
#include <linux/random.h>
#include <stdio.h>

using namespace std;

int EncryptedCom::read_file(string path, unsigned char** file_content) const{
    ifstream file;
    file.open(path);
    if(!file.is_open()){
        cout << "Cannot open the file" << endl;
        return -1;
    }
    file.seekg(0, ios::end);
    int input_length = file.tellg();
    *file_content = new unsigned char [input_length + 16 * sizeof(unsigned char)];
    file.seekg(0, ios::beg);
    file.read((char*)*file_content, input_length);
    
    return input_length;
}    

void EncryptedCom::create_hash(unsigned char* &content, unsigned char sha_result[64], int length) const{
    mbedtls_sha512(content, length, sha_result, 0);   
}

void EncryptedCom::generate_iv(){
    srand((unsigned)time(0));
    for(int i = 0; i < 16; i++)
        iv[i] = (rand()%256);
}

void EncryptedCom::generate_key(unsigned char *key){
    if(key == nullptr)
        return;
    srand((unsigned)time(0)); 
    for(int i = 0; i < 16; i++){
        key[i] = (rand()%256);
    }
}

int EncryptedCom::padding(unsigned char* &content, int length) const{
    int pad = 0;
    if (length % 16 == 0)
        pad = 16;
    else
        pad = 16 - (length % 16);
    
    for(int i = 0; i < pad; i++){
        content[length + i] = pad;
    }
    return length + pad;
}

bool EncryptedCom::encryption(unsigned char* &content, unsigned char* &output, int length, unsigned char *key) const{
    mbedtls_aes_context aes;
    
    if( key == nullptr){
        return false;
    }
    
    if (length <= 0){
        cout << "Encryption err: length is not valid" << endl;
        return false;
    }
    
    if (mbedtls_aes_setkey_enc(&aes, key, 128)){
        cout << "Encryption err: setkey_enc error" << endl;
        return false;
    }
    int new_size = padding(content, length);
    unsigned char en_iv[16];
    memcpy(en_iv, iv, sizeof(unsigned char) * 16);
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, new_size, en_iv, content, output)){
        cout << "Encryption err: aes_crypt error" << endl;
        return false;
    }
    return true;
}

void EncryptedCom::write_file(const char* path, unsigned char* &content) const{
    ofstream file;
    file.open(path, ios::out);
    file << content;
}



bool EncryptedCom::decryption(unsigned char* &content, unsigned char* &output, int length, unsigned char *key) const{
    mbedtls_aes_context aes;
    
    if(key == nullptr)
        return false;
    
    if (length < 0 || length % 16){
        cout << "Decryption err: length is not valid" << endl;
        return false;
    }
    if (mbedtls_aes_setkey_dec(&aes, key, 128)){
        cout << "Decryption err: setkey_dec error" << endl;
        return false;
    }
    unsigned char dec_iv[16];
    memcpy(dec_iv, iv, sizeof(unsigned char) * 16);
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, dec_iv, content, output)){
        cout << "Decryption err: aes_decrypt error" << endl;
        return false;
    }
    int pad = output[length - 1];
    output[length - pad] = '\0';
    return true;
}