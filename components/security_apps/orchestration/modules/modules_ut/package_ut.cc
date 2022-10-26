#include "package.h"

#include "cptest.h"
#include "cereal/types/string.hpp"
#include "cereal/archives/json.hpp"
#include <string>
#include <memory>
#include <fstream>

using namespace testing;
using namespace std;

class PackageTest : public Test
{
public:
    PackageTest() {}

    bool
    load(stringstream &string_stream, Package &package)
    {
        try {
            cereal::JSONInputArchive archive_in(string_stream);
            package.serialize(archive_in);
        } catch (const cereal::Exception &) {
            return false;
        }
        return true;
    }

    void
    write(const string &path, Package &package)
    {
        std::ofstream os(path);
        cereal::JSONOutputArchive archive_out(os);
        package.serialize(archive_out);
    }

    string
    readFile(const string &path)
    {
        ifstream text_file(path);
        stringstream buffer;
        buffer << text_file.rdbuf();
        return buffer.str();
    }
};

TEST_F(PackageTest, doNothing)
{
}

TEST_F(PackageTest, serializationFromString)
{
    stringstream string_stream;
    string_stream <<   "{"
                        "   \"version\": \"c\","
                        "   \"download-path\": \"https://a/install_orchestration.sh\",\n"
                        "   \"relative-path\": \"/install_orchestration.sh\",\n"
                        "   \"name\": \"orchestration\","
                        "   \"checksum-type\": \"sha1sum\","
                        "   \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\","
                        "   \"package-type\": \"service\","
                        "   \"require\": []"
                        "}";
    Package package;
    EXPECT_EQ(true, load(string_stream, package));

    vector<string> links = { "https://10.0.0.18/install_orchestration.sh", "ftp://172.23.92.135/policy.txt" };

    EXPECT_EQ("orchestration", package.getName());
    EXPECT_EQ(Package::ChecksumTypes::SHA1, package.getChecksumType());
    EXPECT_EQ("8d4a5709673a05b380ba7d6567e28910019118f5", package.getChecksum());
    EXPECT_EQ("orchestration", package.getName());
    EXPECT_EQ("c", package.getVersion());
    EXPECT_EQ(Package::PackageType::Service, package.getType());
    EXPECT_TRUE(package.isInstallable().ok());
}

TEST_F(PackageTest, writeAsJson)
{
    stringstream string_stream;
    string_stream <<    "{\n"
                        "    \"download-path\": \"https://a/install_orchestration.sh\",\n"
                        "    \"relative-path\": \"/install_orchestration.sh\",\n"
                        "    \"version\": \"c\",\n"
                        "    \"name\": \"orchestration\",\n"
                        "    \"checksum-type\": \"sha1sum\",\n"
                        "    \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\",\n"
                        "    \"package-type\": \"service\"\n"
                        "}";
    Package package;
    EXPECT_EQ(true, load(string_stream, package));

    vector<string> links = { "https://10.0.0.18/install_orchestration.sh", "ftp://172.23.92.135/policy.txt" };

    EXPECT_EQ("orchestration", package.getName());
    EXPECT_EQ(Package::ChecksumTypes::SHA1, package.getChecksumType());
    EXPECT_EQ("8d4a5709673a05b380ba7d6567e28910019118f5", package.getChecksum());
    EXPECT_EQ("orchestration", package.getName());
    EXPECT_EQ("c", package.getVersion());
    EXPECT_EQ(Package::PackageType::Service, package.getType());
    EXPECT_TRUE(package.isInstallable().ok());

    write("service.json", package);
    string data = readFile("service.json");
    EXPECT_EQ(string_stream.str(), data);
}

TEST_F(PackageTest, eqService)
{
    stringstream string_stream;
    string_stream <<    "{\n"
                        "    \"download-path\": \"https://a/install_orchestration.sh\",\n"
                        "    \"relative-path\": \"/install_orchestration.sh\",\n"
                        "    \"version\": \"c\",\n"
                        "    \"name\": \"orchestration\",\n"
                        "    \"checksum-type\": \"sha1sum\",\n"
                        "    \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\",\n"
                        "    \"package-type\": \"service\"\n"
                        "}";
    Package package;
    Package package2;
    EXPECT_TRUE(load(string_stream, package));
    string_stream.clear();
    string_stream <<    "{\n"
                    "    \"download-path\": \"https://a/install_orchestration.sh\",\n"
                    "    \"relative-path\": \"/install_orchestration.sh\",\n"
                    "    \"version\": \"c\",\n"
                    "    \"name\": \"orchestration\",\n"
                    "    \"checksum-type\": \"sha1sum\",\n"
                    "    \"checksum\": \"8d4a5709673a05b380ba7d6567e28910000000000\",\n"
                    "    \"package-type\": \"service\"\n"
                    "}";
    EXPECT_TRUE(load(string_stream, package));
    EXPECT_TRUE(package != package2);
}

TEST_F(PackageTest, changeDir)
{
    stringstream string_stream;
    string_stream <<    "{\n"
                        "    \"download-path\": \"https://a/install_orchestration.sh\",\n"
                        "    \"relative-path\": \"/install_orchestration.sh\",\n"
                        "    \"version\": \"c\",\n"
                        "    \"name\": \"../..\",\n"
                        "    \"checksum-type\": \"sha1sum\",\n"
                        "    \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\",\n"
                        "    \"package-type\": \"service\"\n"
                        "}";
    Package package;
    EXPECT_FALSE(load(string_stream, package));
}

TEST_F(PackageTest, mkdirCommand)
{
    stringstream string_stream;
    string_stream <<    "{\n"
                        "    \"download-path\": \"https://a/install_orchestration.sh\",\n"
                        "    \"relative-path\": \"/install_orchestration.sh\",\n"
                        "    \"version\": \"c\",\n"
                        "    \"name\": \"mkdir ../../something\",\n"
                        "    \"checksum-type\": \"sha1sum\",\n"
                        "    \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\",\n"
                        "    \"package-type\": \"service\"\n"
                        "}";
    Package package;
    EXPECT_FALSE(load(string_stream, package));
}

TEST_F(PackageTest, badPackageName)
{
    stringstream string_stream;
    string_stream <<    "{\n"
                        "    \"download-path\": \"https://a/install_orchestration.sh\",\n"
                        "    \"relative-path\": \"/install_orchestration.sh\",\n"
                        "    \"version\": \"c\",\n"
                        "    \"name\": \"- - - - - -\",\n"
                        "    \"checksum-type\": \"sha1sum\",\n"
                        "    \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\",\n"
                        "    \"package-type\": \"service\"\n"
                        "}";
    Package package;
    EXPECT_FALSE(load(string_stream, package));
}

TEST_F(PackageTest, anyOrder)
{
    stringstream string_stream;
    string_stream <<    "{\n"
                        "    \"name\": \"asdQwe\",\n"
                        "    \"relative-path\": \"/install_orchestration.sh\",\n"
                        "    \"version\": \"c\",\n"
                        "    \"download-path\": \"https://a/install_orchestration.sh\",\n"
                        "    \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\",\n"
                        "    \"package-type\": \"service\",\n"
                        "    \"checksum-type\": \"sha1sum\"\n"
                        "}";
    Package package;
    EXPECT_TRUE(load(string_stream, package));
}

TEST_F(PackageTest, anyOrderWithRequire)
{
    stringstream string_stream;
    string_stream <<    "{\n"
                        "    \"require\": [],\n"
                        "    \"name\": \"asdQwe\",\n"
                        "    \"version\": \"c\",\n"
                        "    \"relative-path\": \"/install_orchestration.sh\",\n"
                        "    \"download-path\": \"https://a/install_orchestration.sh\",\n"
                        "    \"checksum\": \"8d4a5709673a05b380ba7d6567e28910019118f5\",\n"
                        "    \"package-type\": \"service\",\n"
                        "    \"checksum-type\": \"sha1sum\"\n"
                        "}";
    Package package;
    EXPECT_TRUE(load(string_stream, package));
}

TEST_F(PackageTest, uninstallablePackage)
{
    stringstream string_stream;
    string_stream <<    "{\n"
                        "    \"name\": \"waap\",\n"
                        "    \"version\": \"\",\n"
                        "    \"download-path\": \"\",\n"
                        "    \"relative-path\": \"\",\n"
                        "    \"checksum\": \"\",\n"
                        "    \"package-type\": \"service\",\n"
                        "    \"checksum-type\": \"sha1sum\",\n"
                        "    \"status\": false,\n"
                        "    \"message\": \"This security app isn't valid for this agent\"\n"
                        "}";
    Package package;
    EXPECT_TRUE(load(string_stream, package));
    EXPECT_THAT(package.isInstallable(), IsError("This security app isn't valid for this agent"));
}
