#pragma once

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <regex>
#include <iomanip>
#include <sstream>
#include "sha.h"
#include <hex.h>
#include <iostream>

enum logType
{
    THREAD = 2,
    DLL = 3,
    WARNING = 5,
    PROMPT = 6,
    UNKNOWN_EVENT = 10,
    ERR = 12,
    INFO = 15,
    CONTEXT_REGISTERS = 31
};
enum architecture
{
    x86 = 0,
    x64 = 1
};

struct dataBlob
{
    uint32_t offset;
    uint32_t size;
};


DWORD getCurrentPromptColor (HANDLE);
void printfColor (const char *, DWORD, HANDLE, ... );
void log (const char *, logType, HANDLE,  ...);

void * parseStringToAddress (std::string);
int parseStringToNumber (std::string, int);
std::string intToHex( uint64_t i );

void centerText(const char *, int);
void centerTextColor (const char *, int , DWORD, HANDLE); 
void centerTextColorDecorate (const char *, int, DWORD, HANDLE );
CryptoPP::byte * SHA1(std::string data);
void digestToHexText (CryptoPP::byte * data, uint32_t size);
uint32_t roundUpTo (uint32_t value, uint32_t valueToRoudup);
uint32_t be2le (uint32_t num);