#ifndef __MOCK_INSTACE_AWARENESS__
#define __MOCK_INSTACE_AWARENESS__

#include "cptest.h"
#include "i_instance_awareness.h"
#include "singleton.h"

class MockInstanceAwareness : public Singleton::Provide<I_InstanceAwareness>::From<MockProvider<I_InstanceAwareness>>
{
public:
    MOCK_METHOD0(getUniqueID, Maybe<std::string>());
    MOCK_METHOD0(getFamilyID, Maybe<std::string>());
    MOCK_METHOD0(getInstanceID, Maybe<std::string>());

    MOCK_METHOD1(getUniqueID, std::string(const std::string &));
    MOCK_METHOD1(getFamilyID, std::string(const std::string &));
    MOCK_METHOD1(getInstanceID, std::string(const std::string &));
};

#endif // __MOCK_INSTACE_AWARENESS__
