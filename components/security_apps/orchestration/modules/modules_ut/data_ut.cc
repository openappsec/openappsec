#include "orchestrator/data.h"

#include "cereal/types/string.hpp"
#include "cereal/archives/json.hpp"
#include <string>
#include <memory>
#include <fstream>

#include "cptest.h"
#include "customized_cereal_map.h"

using namespace testing;
using namespace std;

class DataTest : public Test
{
public:
    bool
    load(stringstream &string_stream, Data &data)
    {
        try {
            cereal::JSONInputArchive archive_in(string_stream);
            data.serialize(archive_in);
        } catch (const cereal::Exception &) {
            return false;
        }
        return true;
    }
};

TEST_F(DataTest, doNothing)
{
}

TEST_F(DataTest, serializationFromString)
{
    stringstream string_stream;
    string_stream <<   "{"
                        "   \"version\": \"c\","
                        "   \"downloadPath\": \"https://a/data.json\",\n"
                        "   \"checksumType\": \"sha1sum\","
                        "   \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\""
                        "}";
    bool res = false;
    Data data;
    try {
        cereal::JSONInputArchive archive_in(string_stream);
        data.serialize(archive_in);
        res = true;
    } catch (const cereal::Exception &) {
    }
    EXPECT_EQ(true, res);

    EXPECT_EQ(Data::ChecksumTypes::SHA1, data.getChecksumType());
    EXPECT_EQ("8d4a5709673a05b380ba7d6567e28910019118f5", data.getChecksum());
    EXPECT_EQ("c", data.getVersion());
    EXPECT_EQ("https://a/data.json", data.getDownloadPath());
}

TEST_F(DataTest, serializationFromStringAsMap)
{
    stringstream string_stream;
    string_stream << "{\n"
        "    \"ips\": {\n"
        "       \"version\": \"c\","
        "       \"downloadPath\": \"https://a/data.json\",\n"
        "       \"checksumType\": \"sha1sum\","
        "       \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\""
        "    }\n"
        "}\n";
    map<string, Data> data;
    bool res = false;
    try {
        cereal::JSONInputArchive archive_in(string_stream);
        cereal::load(archive_in, data);
        res = true;
    } catch (const cereal::Exception &e) {
    }
    EXPECT_EQ(true, res);

    EXPECT_EQ(Data::ChecksumTypes::SHA1, data["ips"].getChecksumType());
    EXPECT_EQ("8d4a5709673a05b380ba7d6567e28910019118f5", data["ips"].getChecksum());
    EXPECT_EQ("c", data["ips"].getVersion());
    EXPECT_EQ("https://a/data.json", data["ips"].getDownloadPath());
}
