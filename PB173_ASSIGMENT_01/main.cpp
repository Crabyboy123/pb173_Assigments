/* 
 * File:   main.cpp
 * Author: Kristian Jakubik
 *
 * Created on February 26, 2016, 5:41 PM
 */

#include <iostream>
#include <string.h>
#include <fstream>
#include <string>
#include <aes.h>
#include <sha512.h>
#include <entropy.h>
#include <ctr_drbg.h>
#include <cstdlib> 
#include <ctime>
#include <string.h>
#include <linux/random.h>

using namespace std;
unsigned char en_iv[16]; 
unsigned char dec_iv[16];


int input_length;
unsigned char pad;

unsigned char key[16];

void read_file(char* path, unsigned char**file_content){
    ifstream file;
    file.open(path);
    if(!file.is_open()){
        cout << "Cannot open the file" << endl;
        exit(-1);
    }
    string tmp;
    char c;
    
    while(file.get(c)){
        tmp += c;
    }
    cout << tmp << endl;
    if(input_length == 0){
        input_length = tmp.length();
        if(input_length % 16){
            pad = 16 - (input_length % 16);
        }
    }
    *file_content = new unsigned char[input_length + pad];
    memcpy(*file_content, tmp.c_str(), input_length);
}    

void create_hash(unsigned char *file_content, unsigned char* sha_result){
    mbedtls_sha512(file_content, input_length, sha_result, 0);   
    cout << sha_result << endl;
}

void generate_key(){
    srand((unsigned)time(0)); 
    for(int i = 0; i < 16; i++){
        key[i] = (rand()%256); 
    }
    for(int i = 0; i < 16; i++)
        en_iv[i] = dec_iv [i] = (rand()%256);
}

void padding(unsigned char* file_content){
    for(int i = 0; i < pad; i++){
        file_content[input_length + i] = pad;
        cout << input_length + i << "  " <<(int) file_content[input_length + i] << endl;
    }
    
}

void encryption(unsigned char* file_content, unsigned char* en_output){
    mbedtls_aes_context aes;
    generate_key();
    if (mbedtls_aes_setkey_enc(&aes, key, 128)){
        cout << "setkey_enc error" << endl;
        delete[] file_content;
        delete[] en_output;
        exit(-1);
    }
    padding(file_content);
    for(int i = 0; i < input_length + pad; i++)
                cout << "TU som " << (int)file_content[i] << endl;
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, input_length + pad, en_iv, file_content, en_output)){
        cout << "aes_crypt error" << endl;
        delete[] file_content;
        delete[] en_output;
        exit(-1);
    }
}

void write_file(unsigned char* en_output){
    ofstream file;
    file.open("encrypt.txt", ios::out);
    file << en_output;
   
}

void decryption(unsigned char **file_content, unsigned char *en_output){
    mbedtls_aes_context aes;
    read_file("encrypt.txt", file_content);
    mbedtls_aes_init( &aes );
    if(mbedtls_aes_setkey_dec(&aes, key, 128)){
        cout << "setkey_dec error" << endl;
        delete[] file_content;
        delete[] en_output;
        exit(-1);
    };
    if(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_length + pad, dec_iv, *file_content, en_output)){
        cout << "aes_decrypt error" << endl;
        delete[] file_content;
        delete[] en_output;
        exit(-1);
    }
    //cout << "AHOJ" << *file_content << endl;
    cout << (int)pad << endl;
    cout << input_length << endl;
    cout << en_output << endl;
}

int main(int argc, char** argv){

    if(argc < 2){
        cout << "Cannot read the file." << endl;
        return -1;
    }
    
    unsigned char* file_content;
    unsigned char* en_output;
    unsigned char sha_result1[64] = {'\0'};
    memset(sha_result1, '\0', sizeof(unsigned char) * 64);
    unsigned char sha_result2[64] = {'\0'};
    memset(sha_result2, '\0', sizeof(unsigned char) * 64);
    
    read_file(argv[1], &file_content);
    en_output = new unsigned char[input_length + pad];
    create_hash(file_content, sha_result1);
    encryption(file_content, en_output);
    write_file(en_output);
    delete[] file_content;
    decryption(&file_content, en_output);
    create_hash(en_output, sha_result2);
    if(memcmp(sha_result1, sha_result2, 64 * sizeof(unsigned char)))
        cout << "Hashes are different" << endl;
    else
        cout << "Hashes are same" << endl;
    delete[] file_content;
    delete[] en_output;
    return 0;
}

