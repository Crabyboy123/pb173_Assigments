/** 
 * @file main.cpp
 * @author Kristian Jakubik
 * @licence MIT Licence
 */

#include "encryption.h"

#include <iostream>
#include <fstream>
#include <stdlib.h>
// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("File testing") {
    unsigned char *s;
    EncryptedCom en;
    std::ofstream file;
    file.open("test_file.txt", std::ios::out);
    file << "012345678901234";
    file.close();
    CHECK(en.read_file(std::string("f.txt"), &s) == -1);
    CHECK(en.read_file(std::string("test_file.txt"), &s) == 15);
    CHECK(memcmp(s, "012345678901234", 15 * sizeof(char)) == 0);
}

TEST_CASE("Encryption/Decryption") {
    unsigned char key[16];
    EncryptedCom en;
    en.generate_key(key);
    unsigned char res[16];
    unsigned char *r = res;
    unsigned char *s = new unsigned char[15];
    memcpy(s, "012345678901234", sizeof(char) * 15);
    CHECK(en.encryption(s, r, 15, nullptr) == false);
    CHECK(en.encryption(s, r, 15, key) == true);
    CHECK(en.decryption(r, s, 16, key) == true);
    CHECK(memcmp(s, "012345678901234", sizeof(char) * 15) == 0);
    key[0] = key[0] + 1;
    en.decryption(r, s, 16, key);
    CHECK(memcmp(s, "012345678901234", sizeof(char) * 15) != 0);
    CHECK(en.decryption(r, s, 16, nullptr) == false);
    CHECK(en.decryption(r, s, 15, nullptr) == false);
    delete [] s;
}
           
TEST_CASE("Hash"){
    EncryptedCom en;
    unsigned char hash1[64];
    unsigned char hash2[64];

    unsigned char *s = new unsigned char[15];
    memcpy(s, "012345678901234", sizeof(char) * 15);
    en.create_hash(s, hash1, 15);
    memcpy(s, "012345678901234", sizeof(char) * 15);
    en.create_hash(s, hash2, 15);
    CHECK(memcmp(hash1, hash2, 64 * sizeof(char)) == 0);
    memcpy(s, "012345678901235", sizeof(char) * 15);
    en.create_hash(s, hash2, 15);
    CHECK(memcmp(hash1, hash2, 64 * sizeof(char)) != 0);
}
