#include "instance_awareness.h"

#include <vector>
#include <string>

#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "environment.h"

using namespace std;
using namespace testing;

class InstanceAwarenessTest : public Test
{
public:
    void
    init(const vector<string> &args)
    {
        auto i_config = Singleton::Consume<Config::I_Config>::from(conf);
        i_config->loadConfiguration(args);
    }

    Maybe<string> getInstanceID() { return getInterface()->getInstanceID(); }
    Maybe<string> getFamilyID() { return getInterface()->getFamilyID(); }
    Maybe<string> getUniqueID() { return getInterface()->getUniqueID(); }

    string getInstanceID(const string &str) { return getInterface()->getInstanceID(str); }
    string getFamilyID(const string &str) { return getInterface()->getFamilyID(str); }
    string getUniqueID(const string &str) { return getInterface()->getUniqueID(str); }

private:
    I_InstanceAwareness * getInterface() { return Singleton::Consume<I_InstanceAwareness>::from(inst_aware); }

    InstanceAwareness inst_aware;
    ConfigComponent conf;
    ::Environment env;
};

TEST_F(InstanceAwarenessTest, emptyInit)
{
    vector<string> args;

    init(args);

    EXPECT_THAT(getInstanceID(), IsError("Instance Awareness isn't active, Error: Flag not found"));
    EXPECT_THAT(getFamilyID(), IsError("Family ID isn't active, Error: Flag not found"));
    EXPECT_THAT(
        getUniqueID(),
        IsError("Can't get instance ID, Error: Instance Awareness isn't active, Error: Flag not found")
    );
}

TEST_F(InstanceAwarenessTest, badFamilyID)
{
    vector<string> args({"--family=../../../etc/passwd", "--id=9"});

    init(args);

    EXPECT_THAT(getInstanceID(),   IsValue("9"));
    EXPECT_THAT(getFamilyID(),     IsError("Family ID isn't active, Error: Illegal flag: family"));
    EXPECT_THAT(getUniqueID(),     IsValue("9"));
}

TEST_F(InstanceAwarenessTest, badInstanceID)
{
    vector<string> args({"--family=073b8744b4c5", "--id=../../../etc/passwd"});

    init(args);

    EXPECT_THAT(getInstanceID(),   IsError("Instance Awareness isn't active, Error: Illegal flag: id"));
    EXPECT_THAT(getFamilyID(),     IsValue("073b8744b4c5"));
    EXPECT_THAT(
        getUniqueID(),
        IsError("Can't get instance ID, Error: Instance Awareness isn't active, Error: Illegal flag: id")
    );
}

TEST_F(InstanceAwarenessTest, emptyInstanceID)
{
    vector<string> args({"--family=073b8744b4c5"});

    init(args);

    EXPECT_THAT(getInstanceID(),   IsError("Instance Awareness isn't active, Error: Flag not found"));
    EXPECT_THAT(getFamilyID(),     IsValue("073b8744b4c5"));
    EXPECT_THAT(
        getUniqueID(),
        IsError("Can't get instance ID, Error: Instance Awareness isn't active, Error: Flag not found")
    );
}

TEST_F(InstanceAwarenessTest, noInstanceID)
{
    vector<string> args({"--family=073b8744b4c5", "--id="});

    init(args);

    EXPECT_THAT(getInstanceID(),   IsError("Instance Awareness isn't active, Error: Flag not found"));
    EXPECT_THAT(getFamilyID(),     IsValue("073b8744b4c5"));
    EXPECT_THAT(
        getUniqueID(),
        IsError("Can't get instance ID, Error: Instance Awareness isn't active, Error: Flag not found")
    );
}

TEST_F(InstanceAwarenessTest, init)
{
    vector<string> args({"--family=073b8744b4c5", "--id=9"});

    init(args);

    EXPECT_THAT(getInstanceID(), IsValue("9"));
    EXPECT_THAT(getFamilyID(),   IsValue("073b8744b4c5"));
    EXPECT_THAT(getUniqueID(),   IsValue("073b8744b4c5_9"));
}

TEST_F(InstanceAwarenessTest, initIDOnly)
{
    vector<string> args({"--id=9"});

    init(args);

    EXPECT_THAT(getUniqueID(),   IsValue("9"));
    EXPECT_THAT(getInstanceID(), IsValue("9"));
    EXPECT_THAT(getFamilyID(),   IsError("Family ID isn't active, Error: Flag not found"));
}

TEST_F(InstanceAwarenessTest, defaultValues)
{
    EXPECT_EQ(getInstanceID("8"), "8");
    EXPECT_EQ(getFamilyID("98113aabd3f5"), "98113aabd3f5");
    EXPECT_EQ(getUniqueID("98113aabd3f5_8"), "98113aabd3f5_8");

    vector<string> args({"--family=073b8744b4c5", "--id=9"});

    init(args);

    EXPECT_EQ(getInstanceID("8"), "9");
    EXPECT_EQ(getFamilyID("98113aabd3f5"), "073b8744b4c5");
    EXPECT_EQ(getUniqueID("98113aabd3f5_8"), "073b8744b4c5_9");
}
