//Author: Alec Wood
//File: Mal1.cpp
//Purpose: Non-malicious script used to immitate malicious injection via process hollowing.

#include <iostream>
#include <windows.h>

int main() {

    MessageBox(NULL, L"Hello World!", L"Greetings!", MB_OK);
    //std::cout << "Hello World!\n";

    return 0;
}

