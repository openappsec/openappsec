#include <gmock/gmock.h>
#include "i_time_get.h"
#include "singleton.h"
#include "cptest.h"

class MockTimeGet : public Singleton::Provide<I_TimeGet>::From<MockProvider<I_TimeGet>>
{
public:
    MOCK_METHOD0(getMonotonicTime, std::chrono::microseconds());
    MOCK_METHOD0(getWalltime,      std::chrono::microseconds());
    MOCK_METHOD0(getWalltimeStr,   std::string());
    MOCK_METHOD0(getLocalTimeStr,     std::string());
    MOCK_METHOD1(getWalltimeStr,   std::string(const std::chrono::microseconds &));
};
