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
#define IV "Dnes si dam caj" 
mbedtls_aes_context aes;

int input_length;
unsigned char pad;

unsigned char key[16];

void read_file(char* path, unsigned char**file_content){
    ifstream file;
    file.open(path);
    string tmp;
 
    char c;
    while(file.get(c)){
        tmp += c;
    }
    cout << tmp << endl;
    input_length = tmp.length();
    if(input_length % 16)
        pad = 16 - input_length % 16;
    *file_content = new unsigned char[input_length + pad];
    memcpy(*file_content, tmp.c_str(), input_length);
    file.close();
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
}

void padding(unsigned char* file_content){
    for(int i = 0; i < pad; i++){
        file_content[input_length + i] = pad;
    }
}

void encryption(unsigned char* file_content, unsigned char* en_output){
    generate_key();
    if (mbedtls_aes_setkey_enc(&aes, key, 128)){
        cout << "setkey_enc error" << endl;
        exit(-1);
    }
    padding(file_content);
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, (unsigned char*)IV, file_content, en_output)){
        cout << "aes_crypt error" << endl;
        exit(-1);
    }
}

int main(int argc, char** argv){

    if(argc < 2){
        cout << "Cannot read the file." << endl;
        return -1;
    }
    
    unsigned char* file_content;
    unsigned char* en_output;
    unsigned char sha_result[64] = {'\0'};
    memset(sha_result, '\0', sizeof(unsigned char) * 64);
    
    read_file(argv[1], &file_content);
    en_output = new unsigned char[input_length];
    create_hash(file_content, sha_result);
    encryption(file_content, en_output);
    delete file_content;
    delete en_output;
    return 0;
}

