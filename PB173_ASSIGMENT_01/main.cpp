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
#include <linux/random.h>

using namespace std;

mbedtls_aes_context aes;

unsigned char key[16];
unsigned char iv[16];

unsigned char input [128];
unsigned char output[128];

size_t input_len = 40;
size_t output_len = 0;

void read_file(char* path, string &file_content){
    ifstream file;
    file.open(path);
    
    char c;
    while(file.get(c)){
        file_content += c;
    }
    cout << file_content << endl;
    
    file.close();
}    

void create_hash(string &file_content, unsigned char* sha_result){
    mbedtls_sha512((unsigned char*)file_content.c_str(), file_content.length(), sha_result, 0);   
    cout << sha_result << endl;
}

void generate_key(){
    
    /*mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    int ret;
    
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg ); 

    if( ( ret = mbedtls_ctr_drbg_random( &ctr_drbg, key, 16 ) ) != 0 )
    {
        printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
        return;
    }
    cout << "Kluce" << endl;
    for(int i = 0; i < 16; i++) cout << key[i] << endl;*/

    srand((unsigned)time(0)); 
    for(int i = 0; i < 16; i++){
        key[i] = (rand()%256); 
    }
}

void encryption(string &file_content){
    generate_key();
    if( mbedtls_aes_setkey_enc(&aes, key, 128) ){
        cout << "setkey_enc error" << endl;
        exit( -1);
    }
    
}

int main(int argc, char** argv){

    if(argc < 2){
        cout << "Cannot read the file." << endl;
        return -1;
    }
    
    string file_content;
    unsigned char sha_result[64] = {'\0'};
    
    read_file(argv[1], file_content);
    create_hash(file_content, sha_result);
    encryption(file_content);
    return 0;
}

