#include <iostream>
#include <string>
#include <vector>

#include "cptest.h"
#include "gtest/gtest.h"
#include "debug.h"

using namespace std;

static string
formatNum(const char *fmt, int n)
{
    char buf[100];
    snprintf(buf, sizeof(buf), fmt, n);
    return string(buf);
}

ostream &
operator<<(ostream &os, const Buffer &buf)
{
    auto len = buf.size();
    auto data = buf.data();
    const int line_chars = 16;
    os << "Buffer Data:" << endl;
    for (uint i = 0; i<(len+line_chars-1)/line_chars; i++) {
        // Line header
        os << formatNum("%04x", i*line_chars) << ":  ";

        // Hex of each character
        for (uint j = 0; j<line_chars; j++) {
            uint pos = i*line_chars + j;
            os << " " << (pos<len ? formatNum("%02x", data[pos]) : "  ");
        }

        os << " ";

        // Printable chars
        for (uint j = 0; j<line_chars; j++) {
            uint pos = i*line_chars + j;
            if (pos >= len) break;
            os << (isprint(data[pos]) ? char(data[pos]) : '.');
        }

        os << endl;
    }
    return os;
}
