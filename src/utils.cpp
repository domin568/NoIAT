#include "utils.hpp"

void printfColor (const char * format, DWORD color, HANDLE stdoutHandle, ...)
{
    WORD savedAttributes = getCurrentPromptColor (stdoutHandle);
    SetConsoleTextAttribute(stdoutHandle, color);
    va_list args;
    va_start(args, stdoutHandle);
    vprintf (format,args); // vprintf when we do not know how many arguments we gonna pass
    va_end (args);
    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
}
void log (const char * messageFormatted, logType type, HANDLE stdoutHandle, ...)
{   
    WORD savedAttributes = getCurrentPromptColor (stdoutHandle);
    SetConsoleTextAttribute(stdoutHandle, type);
    switch (type)
    {
        case logType::CONTEXT_REGISTERS:
        {
            va_list args;
            va_start(args, stdoutHandle);
            vprintf (messageFormatted,args); // vprintf when we do not know how many arguments we gonna pass
            va_end (args);
            SetConsoleTextAttribute(stdoutHandle, savedAttributes);
            printf ("\n");
            return;
        }
        case logType::THREAD:
        {
            printf ("[+] ");
            break;
        }
        case logType::DLL:
        {
            printf ("[+] ");
            break;
        }
        case logType::WARNING:
        {
            printf ("[!] ");
            break;
        }
        case logType::PROMPT:
        {
            printf ("%s","maldbg> ");
            SetConsoleTextAttribute(stdoutHandle, savedAttributes);
            return;
        }
        case logType::INFO:
        {
            printf ("[*] ");
            break;
        }
        case logType::ERR:
        {
            printf ("[!] ");
            break;
        }
        case logType::UNKNOWN_EVENT:
        {
            printf ("[?] ");
            break;
        }
    }    
    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
    va_list args;
    va_start(args, stdoutHandle);
    vprintf (messageFormatted,args); // vprintf when we do not know how many arguments we gonna pass
    va_end (args);
}
DWORD getCurrentPromptColor (HANDLE stdoutHandle)
{
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo);
    return consoleInfo.wAttributes;
}

void* parseStringToAddress (std::string toConvert)
{
    void * address;
    sscanf (toConvert.c_str(),"%llx", &address);
    return address;
}
int parseStringToNumber (std::string toConvert, int base = 10)
{
    uint64_t number {0};
    if (base == 10)
    {
        sscanf (toConvert.c_str(), "%lli", &number);
    }
    else if (base == 16)
    {
        sscanf (toConvert.c_str(), "%llx", &number);
    }
    return number;
}
void centerText (const char *text, int fieldWidth) 
{
    int padLen = (fieldWidth - strlen(text)) / 2;
    printf("%*c%s%*c", padLen, " " , text, (strlen(text) % 2 == 1 ? padLen + 1 : padLen), " ");
}
void centerTextColor (const char *text, int fieldWidth, DWORD color, HANDLE stdoutHandle) 
{
    WORD savedAttributes = getCurrentPromptColor (stdoutHandle);
    SetConsoleTextAttribute(stdoutHandle, color);
    int padLen = (fieldWidth - strlen(text)) / 2;
    printf("%*s%s%*s", padLen, " " , text, (strlen(text) % 2 == 1 ? padLen + 1 : padLen), " ");

    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
}
void centerTextColorDecorate (const char *text, int fieldWidth, DWORD color, HANDLE stdoutHandle) 
{
    WORD savedAttributes = getCurrentPromptColor (stdoutHandle);
    SetConsoleTextAttribute(stdoutHandle, color);
    int padLen = (fieldWidth - strlen(text)) / 2;

    printf ("%.*s %s %.*s",
    padLen-1,
    "=============================================================================================",
    text,
    (strlen(text) % 2 == 1 ? padLen : padLen - 1),
    "============================================================================================="
    );
    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
} 
std::string intToHex( uint64_t i )
{
  std::stringstream stream;
  stream << "0x" 
         << std::hex << i;
  return stream.str();
}
CryptoPP::byte * SHA1(std::string data)
{
    byte const* pbData = (byte*) data.data();
    unsigned int nDataLen = data.size();
    CryptoPP::byte * abDigest = new CryptoPP::byte[CryptoPP::SHA1::DIGESTSIZE];

    CryptoPP::SHA1().CalculateDigest(abDigest, pbData, nDataLen);

    return abDigest;
}
void digestToHexText (CryptoPP::byte * data, uint32_t size)
{
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( data, size );
    encoder.MessageEnd();
    std::cout << output << std::endl;
}
uint32_t roundUpTo (uint32_t value, uint32_t valueToRoudup)
{
    return valueToRoudup + valueToRoudup * (value / valueToRoudup);
}
uint32_t be2le (uint32_t num)
{
    return ((num>>24)&0xff) | // move byte 3 to byte 0
                    ((num<<8)&0xff0000) | // move byte 1 to byte 2
                    ((num>>8)&0xff00) | // move byte 2 to byte 1
                    ((num<<24)&0xff000000); // byte 0 to byte 3
}