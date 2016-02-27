/* 
 * File:   main.cpp
 * Author: Kristian Jakubik
 *
 * Created on February 26, 2016, 5:41 PM
 */

#include <iostream>
#include <fstream>
#include <string>

using namespace std;

void read_file(char* path){
    ifstream file;
    file.open(path);
    
    string result;
    char c;
    while(file.get(c)){
        result += c;
    }
    cout << result << endl;
    file.close();
}    

int main(int argc, char** argv) {

    if(argc < 2)
        cout << "Cannot read the file." << endl;
    read_file(argv[1]);
    return 0;
}

