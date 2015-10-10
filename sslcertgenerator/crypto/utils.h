#ifndef UTILS_H
#define UTILS_H

#include "vector"

class utils
{
public:
    utils();

    static void printBinaryFormattedCert(std::vector<char> data,int length);

    static void printHexFormattedCert(std::vector<char> data,int length);

};

#endif // UTILS_H
