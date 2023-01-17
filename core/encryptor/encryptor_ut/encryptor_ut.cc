#include "encryptor.h"

#include "config.h"
#include "config_component.h"
#include "cptest.h"
#include "mock/mock_time_get.h"
#include "mock/mock_mainloop.h"

using namespace testing;
using namespace std;

class EncryptorTest : public Test
{
public:
    EncryptorTest()
    {
        i_encryptor = Singleton::Consume<I_Encryptor>::from(encryptor);
    }

    ~EncryptorTest() {}

    I_Encryptor *i_encryptor;
    Encryptor encryptor;
};

TEST_F(EncryptorTest, doNothing)
{
}

TEST_F(EncryptorTest, registerExpectedConfig)
{
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ::Environment env;
    ConfigComponent config;
    env.preload();
    encryptor.preload();
    env.init();
    setConfiguration(
        string("this is new dir path"),
        string("encryptor"),
        string("Data files directory")
    );
    EXPECT_THAT(
        getConfiguration<string>("encryptor", "Data files directory"),
        IsValue(string("this is new dir path"))
    );
    env.fini();
}

TEST_F(EncryptorTest, base64Decode)
{
    EXPECT_EQ(i_encryptor->base64Decode(""), "");
    EXPECT_EQ(i_encryptor->base64Decode("SGVsbG8gV29ybGQh"), "Hello World!");
}

TEST_F(EncryptorTest, base64Encode)
{
    EXPECT_EQ(i_encryptor->base64Encode(""), "");
    EXPECT_EQ(i_encryptor->base64Encode("Hello World!"), "SGVsbG8gV29ybGQh");
}

TEST_F(EncryptorTest, XOREncrypt)
{
    EXPECT_EQ(i_encryptor->obfuscateXor(""), string(""));
    EXPECT_EQ(i_encryptor->obfuscateXor("ABCDEF"), string("\x2\xa\x6\x7\xe\x16"));
    EXPECT_EQ(i_encryptor->obfuscateXor("CHECKPOINT"),  string("\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 10));
    EXPECT_EQ(i_encryptor->obfuscateXor("asdqweasdqwe"), string("\x22\x3b\x21\x32\x3c\x35\x2e\x3a\x2a\x25\x34\x2d"));
}

TEST_F(EncryptorTest, XORDecrypt)
{
    EXPECT_EQ(i_encryptor->obfuscateXor(""), string(""));
    EXPECT_EQ(i_encryptor->obfuscateXor(string("\x2\xa\x6\x7\xe\x16")), "ABCDEF");
    EXPECT_EQ(i_encryptor->obfuscateXor(string("\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 10)), "CHECKPOINT");
    EXPECT_EQ(i_encryptor->obfuscateXor(string("\x22\x3b\x21\x32\x3c\x35\x2e\x3a\x2a\x25")), "asdqweasdq");
}

TEST_F(EncryptorTest, XORBase64Encrypt)
{
    EXPECT_EQ(i_encryptor->obfuscateXorBase64(""), string(""));
    EXPECT_EQ(
        i_encryptor->obfuscateXorBase64(string("\x0b\x2d\x29\x2f\x24\x70\x18\x26\x3c\x38\x27\x69")), "SGVsbG8gV29ybGQh"
    );
}

