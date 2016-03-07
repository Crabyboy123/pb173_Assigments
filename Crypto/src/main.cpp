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
#include "encryption.h"
#include "aes.h"
#include "sha512.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include <cstdlib> 
#include <ctime>
#include <string.h>
#include <linux/random.h>
#include <stdio.h>

using namespace std;

int main(int argc, char** argv){

    string path;
    cout << "Enter the path to the file:" << endl;
    cin >> path;
    unsigned char sha_result1[64];
    unsigned char sha_result2[64];
    EncryptedCom en;
    unsigned char* file_content;
    int size;
    if((size = en.read_file(path, &file_content)) < 0){
        return 1;
    }    
    unsigned char* en_output = new unsigned char[size + 16];
    unsigned char key[16];
    en.generate_key((unsigned char*)key);
    en.create_hash(file_content, sha_result1, size);
    
    en.encryption(file_content, en_output, size, (unsigned char *)key);
    
    en.write_file("encryption.txt",en_output);
    delete[] en_output;
    delete[] file_content;
    
    if((size = en.read_file("encryption.txt", &file_content)) <= 0){
        return 1;
    }
    
    en_output = new unsigned char[size];
    
    en.decryption(file_content, en_output, size, (unsigned char *)key);
    cout << "File: " << en_output << endl;
    en.create_hash(en_output, sha_result2, strlen((const char*)en_output));
    
    if(memcmp(sha_result1, sha_result2, 64 * sizeof(unsigned char)))
        cout << "Hashes are different" << endl;
    else
        cout << "Hashes are same" << endl;
    delete[] file_content;
    delete[] en_output;
    return 0;
}

