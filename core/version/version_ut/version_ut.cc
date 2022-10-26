#include "version.h"
#include "cptest.h"
#include "mock/mock_rest_api.h"
#include "environment.h"
#include "config.h"
#include "time_proxy.h"
#include "mainloop.h"

using namespace std;
using namespace testing;

TEST(Version, format)
{
    // Time format: 2016-11-20T11:09:58+0200
    EXPECT_THAT(
        Version::getTimestamp(),
        ContainsRegex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[-+][0-9]{4}")
    );

    // "Build 123" or "GitID 7d67870"
    EXPECT_THAT(Version::getID(), ContainsRegex("([0-9]+)|[0-9]{4}.([0-9]+)"));

    // get() return all parts of information, timestamp and id.
    EXPECT_THAT(Version::get(), ContainsRegex("([0-9]+)|[0-9]{4}.([0-9]+)"));
    EXPECT_THAT(Version::get(), ContainsRegex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[-+][0-9]{4}"));
}

TEST(Version, getVerPrefix)
{
    EXPECT_EQ("1.", Version::getVerPrefix());
}

TEST(Version, getUser)
{
    if (Version::isPublic()) {
        // public builds call this function but don't use the return value
        // ut will do the same, as the user name is not accessible in public builds.
        auto user = Version::getUser();
        
        const char* buffer = getenv("CI_BUILD_REF_NAME");
        ASSERT_FALSE(!buffer);
        EXPECT_THAT(Version::getBranch(), AnyOf(buffer, StartsWith("pipeline")));
    } else {
        // Version::getUser is define by the python function: getpass.getuser().
        // The getuser() function displays the login name of the user.
        // This function checks the environment variables LOGNAME, USER, LNAME and USERNAME, in order,
        // and returns the value of the first non-empty string.
        const char* buffer = getenv("LOGNAME");
        if (!buffer) {
            buffer = getenv("USER");
            if (!buffer) {
                buffer = getenv("LNAME");
                if (!buffer) {
                    buffer = getenv("USERNAME");
                }
            }
        }
        ASSERT_FALSE(!buffer);
        EXPECT_EQ(buffer, Version::getUser());
        EXPECT_EQ(Version::getBranch(), "private");
    }
}

unique_ptr<ServerRest> show_version;
bool showVersion(const unique_ptr<RestInit> &p) { show_version = p->getRest(); return true; }

TEST(Version, init)
{
    StrictMock<MockRestApi> mock_rs;
    ::Environment env;

    EXPECT_CALL(mock_rs, mockRestCall(RestAction::SHOW, "version-info", _)).WillOnce(WithArg<2>(Invoke(showVersion)));

    Version::init();

    stringstream is;
    is << "{}";
    auto output = show_version->performRestCall(is);

    string res;
    if (Version::isPublic()) {
        string branch;
        if (Version::getBranch() != "master") branch = ("-" + Version::getBranch());
        res =
            "{\n"
            "    \"type\": \"public\",\n"
            "    \"timestamp\": \"" + Version::getTimestamp() + "\",\n"
            "    \"version\": \"" + Version::getVerPrefix() + Version::getID() + branch + "\"\n"
            "}";
    } else {
        res =
            "{\n"
            "    \"type\": \"private\",\n"
            "    \"timestamp\": \"" + Version::getTimestamp() + "\",\n"
            "    \"user\": \"" + Version::getUser() + "\",\n"
            "    \"commit\": \"" + Version::getID() + "\"\n"
            "}";
    }

    EXPECT_THAT(output, IsValue(res));
}
