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

    EXPECT_THAT(Version::get(), ContainsRegex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[-+][0-9]{4}"));
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
