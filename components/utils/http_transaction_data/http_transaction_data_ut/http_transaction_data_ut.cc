#include "http_transaction_data.h"

#include <string>
#include <sstream>

#include "cptest.h"

using namespace std;
using namespace testing;

Buffer
encodeInt16(uint16_t val)
{
    vector<u_char> raw_data(reinterpret_cast<u_char*>(&val), reinterpret_cast<u_char*>(&val) + sizeof(uint16_t));
    return move(Buffer(raw_data));
}

class HttpTransactionTest : public Test
{
public:
    Buffer
    createValidBuf()
    {
        Buffer protocol_length = Buffer(encodeInt16(strlen("HTTP/1.1")));

        return
            protocol_length +
            Buffer("HTTP/1.1") +
            encodeInt16(3) +
            Buffer("GET") +
            encodeInt16(9) +
            Buffer("localhost") +
            encodeInt16(7) +
            Buffer("0.0.0.0") +
            encodeInt16(443) +
            encodeInt16(10) +
            Buffer("/user-app/") +
            encodeInt16(9) +
            Buffer("127.0.0.1") +
            encodeInt16(47423);
    }

    Buffer
    createBadVerBuf()
    {
        Buffer protocol_length = Buffer(encodeInt16(strlen("HTTP/1.1")));

        return
            protocol_length +
            Buffer("HTTP/1");
    }

    Buffer
        createBadAddressBuf()
        {
            Buffer protocol_length = Buffer(encodeInt16(strlen("HTTP/1.1")));

            return
                protocol_length +
                Buffer("HTTP/1.1") +
                encodeInt16(3) +
                Buffer("GET") +
                encodeInt16(9) +
                Buffer("localhost") +
                encodeInt16(14) +
                Buffer("this.is.not.IP") +
                encodeInt16(443) +
                encodeInt16(10) +
                Buffer("/user-app/") +
                encodeInt16(9) +
                Buffer("127.0.0.1") +
                encodeInt16(47423);
        }
};

TEST_F(HttpTransactionTest, TestEmptyTransactionData)
{
    HttpTransactionData data;
    stringstream data_stream;
    data.print(data_stream);
    string data_string(
        " GET\nFrom: Uninitialized IP address:65535\nTo:  (listening on Uninitialized IP address:65535)\n"
    );
    EXPECT_EQ(data_stream.str(), data_string);
}

TEST_F(HttpTransactionTest, TestTransactionDataFromBuf)
{
    HttpTransactionData data = HttpTransactionData::createTransactionData(createValidBuf()).unpack();
    stringstream data_stream;
    data.print(data_stream);
    string data_string(
        "HTTP/1.1 GET\nFrom: 127.0.0.1:47423\nTo: localhost/user-app/ (listening on 0.0.0.0:443)\n"
    );
    EXPECT_EQ(data_stream.str(), data_string);

    EXPECT_EQ(data.getSourceIP(), IPAddr::createIPAddr("127.0.0.1").unpack());
    EXPECT_EQ(data.getSourcePort(), 47423);
    EXPECT_EQ(data.getListeningIP(), IPAddr::createIPAddr("0.0.0.0").unpack());
    EXPECT_EQ(data.getListeningPort(), 443);
    EXPECT_EQ(data.getDestinationHost(), "localhost");
    EXPECT_EQ(data.getHttpProtocol(), "HTTP/1.1");
    EXPECT_EQ(data.getURI(), "/user-app/");
    EXPECT_EQ(data.getHttpMethod(), "GET");
    EXPECT_EQ(data.getParsedURI(), "/user-app/");
    EXPECT_EQ(data.getParsedHost(), "localhost");
}

TEST_F(HttpTransactionTest, TestTransactionDataBadVer)
{
    auto data = HttpTransactionData::createTransactionData(createBadVerBuf());
    ASSERT_FALSE(data.ok());
    EXPECT_EQ(
        data.getErr(),
        "Could not deserialize HTTP protocol: "
        "Failed to get String param Cannot get internal pointer beyond the buffer limits"
    );
}

TEST_F(HttpTransactionTest, TestTransactionDataBadAddress)
{
    auto data = HttpTransactionData::createTransactionData(createBadAddressBuf());
    ASSERT_FALSE(data.ok());
    EXPECT_EQ(
        data.getErr(),
        "Could not deserialize listening address: "
        "Could not parse IP Address: String 'this.is.not.IP' is not a valid IPv4/IPv6 address"
    );
}

TEST_F(HttpTransactionTest, TestTransactionDataFromBufWIthParsedHostAndParsedUri)
{
    Buffer meta_data =
        Buffer(encodeInt16(strlen("HTTP/1.1"))) +
        Buffer("HTTP/1.1") +
        encodeInt16(3) +
        Buffer("GET") +
        encodeInt16(9) +
        Buffer("localhost") +
        encodeInt16(7) +
        Buffer("0.0.0.0") +
        encodeInt16(443) +
        encodeInt16(11) +
        Buffer("//user-app/") +
        encodeInt16(9) +
        Buffer("127.0.0.1") +
        encodeInt16(47423) +
        encodeInt16(10) +
        Buffer("localhost2") +
        encodeInt16(10) +
        Buffer("/user-app/");

    HttpTransactionData data = HttpTransactionData::createTransactionData(meta_data).unpack();
    stringstream data_stream;
    data.print(data_stream);
    string data_string(
        "HTTP/1.1 GET\nFrom: 127.0.0.1:47423\nTo: localhost//user-app/ (listening on 0.0.0.0:443)\n"
    );
    EXPECT_EQ(data_stream.str(), data_string);

    EXPECT_EQ(data.getSourceIP(), IPAddr::createIPAddr("127.0.0.1").unpack());
    EXPECT_EQ(data.getSourcePort(), 47423);
    EXPECT_EQ(data.getListeningIP(), IPAddr::createIPAddr("0.0.0.0").unpack());
    EXPECT_EQ(data.getListeningPort(), 443);
    EXPECT_EQ(data.getDestinationHost(), "localhost");
    EXPECT_EQ(data.getHttpProtocol(), "HTTP/1.1");
    EXPECT_EQ(data.getURI(), "//user-app/");
    EXPECT_EQ(data.getHttpMethod(), "GET");
    EXPECT_EQ(data.getParsedURI(), "/user-app/");
    EXPECT_EQ(data.getParsedHost(), "localhost2");
}
