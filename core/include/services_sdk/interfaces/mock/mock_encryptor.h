#ifndef __MOCK_ENCRYPTOR_H__
#define __MOCK_ENCRYPTOR_H__

#include "i_encryptor.h"
#include "cptest.h"

class MockEncryptor : public Singleton::Provide<I_Encryptor>::From<MockProvider<I_Encryptor>>
{
public:
    // Base64
    MOCK_METHOD1(base64Encode, std::string(const std::string &));
    MOCK_METHOD1(base64Decode, std::string(const std::string &));

    // Obfuscating
    MOCK_METHOD1(obfuscateXor, std::string(const std::string &));
    MOCK_METHOD1(obfuscateXorBase64, std::string(const std::string &));


};

#endif //__MOCK_ENCRYPTOR_H__
