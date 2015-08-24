#include "utils.h"
#include "iostream"
#include "string"
#include <fstream>

using namespace std;

utils::utils()
{
}

void utils::printBinaryFormattedCert(char * data,int length)
{
    for (int i = 0; i  < length;i++)
    {
        for (int j = 7; j >= 0; j --)
        {
        if ( (data[i] & (1 << j)) )
            printf("%d", 1);
        else
            printf("%d", 0);
        }
    }
}

void utils::printHexFormattedCert(char * data,int length)
{
    char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',   'B','C','D','E','F'};

    char group=0;
    std::string str;
    for (int i = 0; i < length; ++i) {
        const char ch = data[i];
        str.append(&hex[(ch  & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
        if (group==1){
            str.append(" ");
            group=0;
        }
        else{
            group++;
        }
    }
    cout << str.data() << endl;
}
