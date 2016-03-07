/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   encryption.h
 * Author: kristian
 *
 * Created on March 4, 2016, 7:11 PM
 */

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <iostream>
class EncryptedCom{
    
    unsigned char iv[16];

public:
    EncryptedCom() { generate_iv(); }
    int read_file(std::string, unsigned char**) const;
    bool encryption(unsigned char*&, unsigned char*&, int, unsigned char *) const;
    void create_hash(unsigned char*&, unsigned char[64], int) const;
    bool decryption(unsigned char*&, unsigned char*&, int, unsigned char *) const;
    void write_file(const char*, unsigned char*&) const;
    void generate_key(unsigned char *);
private:
    void generate_iv();
    int padding(unsigned char*&, int) const;
};


#endif /* ENCRYPTION_H */

