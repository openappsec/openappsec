#include "agent_details.h"

#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>

#include "mock/mock_encryptor.h"
#include "mock/mock_shell_cmd.h"
#include "mock/mock_mainloop.h"
#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "buffer.h"
#include "cptest.h"

using namespace std;
using namespace testing;

class AgentDetailsTest : public Test
{
public:
    AgentDetailsTest()
    {
        config = Singleton::Consume<Config::I_Config>::from(conf);
    }

    ::Environment env;
    ConfigComponent conf;
    StrictMock<MockEncryptor> mock_encryptor;
    StrictMock<MockShellCmd> mock_shell_cmd;
    Config::I_Config *config = nullptr;
    StrictMock<MockMainLoop> mock_ml;
};

