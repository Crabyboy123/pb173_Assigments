/* 
 * File:   main.cpp
 * Author: Kristian Jakubik
 *
 * Created on February 26, 2016, 5:41 PM
 */

#include <iostream>
#include <fstream>
#include <string>
#include <aes.h>
#include <sha512.h>

using namespace std;

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

int main(int argc, char** argv){

    if(argc < 2){
        cout << "Cannot read the file." << endl;
        return -1;
    }
    
    string file_content;
    unsigned char sha_result[64] = {""};
    
    read_file(argv[1], file_content);
    create_hash(file_content, sha_result);
    return 0;
}

