#include "orchestration_tools.h"

#include "cptest.h"

using namespace std;
using namespace testing;

class OrchestrationToolsTest : public Test
{
public:
    OrchestrationToolsTest() : manifest_file("manifest.json")
    {
    }

    void
    cleanSpaces(string &str)
    {
        str.erase(remove(str.begin(), str.end(), ' '), str.end());
    }

    OrchestrationTools orchestration_tools;
    I_OrchestrationTools *i_orchestration_tools = Singleton::Consume<I_OrchestrationTools>::from(orchestration_tools);
    string manifest_file = "manifest.json";
    string manifest_text =  "{"
                            "    \"packages\": ["
                            "        {"
                            "            \"download-path\": \"https://a/install_orchestration.sh\","
                            "            \"relative-path\": \"/install_orchestration.sh\","
                            "            \"name\": \"l4_firewall\","
                            "            \"version\": \"b\","
                            "            \"checksum-type\": \"sha1sum\","
                            "            \"checksum\": \"206afe939eb53168d70fbb777afb4e814097c4dc\","
                            "            \"package-type\": \"service\","
                            "            \"require\": []"
                            "        },"
                            "        {"
                            "            \"name\": \"orchestration\","
                            "            \"download-path\": \"https://a/install_orchestration.sh\","
                            "            \"relative-path\": \"/install_orchestration.sh\","
                            "            \"version\": \"c\","
                            "            \"checksum-type\": \"md5sum\","
                            "            \"checksum\": \"04417eef36f93cec4ca7a435bdcd004508dbaa83\","
                            "            \"package-type\": \"service\","
                            "            \"require\": []"
                            "        }"
                            "    ]"
                            "}";
};

TEST_F(OrchestrationToolsTest, doNothing)
{
}

TEST_F(OrchestrationToolsTest, writeReadTextToFile)
{
    EXPECT_TRUE(i_orchestration_tools->writeFile(manifest_text, manifest_file));
    EXPECT_TRUE(i_orchestration_tools->doesFileExist(manifest_file));
    EXPECT_TRUE(i_orchestration_tools->isNonEmptyFile(manifest_file));
    EXPECT_EQ(manifest_text, i_orchestration_tools->readFile(manifest_file).unpack());

    EXPECT_FALSE(i_orchestration_tools->isNonEmptyFile("no_such_file"));
}

TEST_F(OrchestrationToolsTest, loadPackagesFromJsonTest)
{
    EXPECT_TRUE(i_orchestration_tools->writeFile("blabla", "in_test.json"));
    string file_name = "in_test.json";
    Maybe<map<string, Package>> packages = i_orchestration_tools->loadPackagesFromJson(file_name);
    EXPECT_FALSE(packages.ok());

    Maybe<string> value = i_orchestration_tools->readFile(manifest_file);
    packages = i_orchestration_tools->loadPackagesFromJson(manifest_file);
    EXPECT_TRUE(packages.ok());
    EXPECT_EQ(2u, packages.unpack().size());
    EXPECT_TRUE(packages.unpack().find("orchestration") != packages.unpack().end());
    EXPECT_TRUE(packages.unpack().find("l4_firewall") != packages.unpack().end());
    EXPECT_TRUE(packages.unpack().find("Hello World") == packages.unpack().end());
}

TEST_F(OrchestrationToolsTest, copyFile)
{
    EXPECT_TRUE(i_orchestration_tools->writeFile("blabla", "in_test.json"));
    EXPECT_TRUE(i_orchestration_tools->copyFile("in_test.json", "cpy_test.json"));
    EXPECT_EQ("blabla", i_orchestration_tools->readFile("cpy_test.json").unpack());
    EXPECT_FALSE(i_orchestration_tools->copyFile("NOT_EXISTS_FILE", "cpy2_test.json"));
    auto read_unexists_file = i_orchestration_tools->readFile("cpy2_test.json");
    EXPECT_FALSE(read_unexists_file.ok());
    EXPECT_THAT(read_unexists_file, IsError("File cpy2_test.json does not exist."));
}

TEST_F(OrchestrationToolsTest, checksumTest)
{
    EXPECT_EQ("df5ea29924d39c3be8785734f13169c6",
        i_orchestration_tools->calculateChecksum(Package::ChecksumTypes::MD5, "in_test.json").unpack());
    EXPECT_EQ("ccadd99b16cd3d200c22d6db45d8b6630ef3d936767127347ec8a76ab992c2ea",
        i_orchestration_tools->calculateChecksum(Package::ChecksumTypes::SHA256, "in_test.json").unpack());
    EXPECT_EQ("bb21158c733229347bd4e681891e213d94c685be",
        i_orchestration_tools->calculateChecksum(Package::ChecksumTypes::SHA1, "in_test.json").unpack());
    EXPECT_EQ("d1c2e12cfeababc8b95daf6902e210b170992e68fd1c1f19565a40cf0099c6e2cb559"
        "b85d7c14ea05b4dca0a790656d003ccade9286827cffdf8e664fd271499",
        i_orchestration_tools->calculateChecksum(Package::ChecksumTypes::SHA512, "in_test.json").unpack());
    EXPECT_NE(
        "12342",
        i_orchestration_tools->calculateChecksum(Package::ChecksumTypes::SHA256, "in_test.json").unpack()
    );
}

TEST_F(OrchestrationToolsTest, removeTestFiles)
{
    EXPECT_TRUE(i_orchestration_tools->doesFileExist(manifest_file));
    EXPECT_TRUE(i_orchestration_tools->removeFile(manifest_file));
    EXPECT_FALSE(i_orchestration_tools->doesFileExist(manifest_file));

    EXPECT_TRUE(i_orchestration_tools->doesFileExist(string("in_test.json")));
    EXPECT_TRUE(i_orchestration_tools->removeFile(string("in_test.json")));
    EXPECT_FALSE(i_orchestration_tools->doesFileExist(string("in_test.json")));

    EXPECT_TRUE(i_orchestration_tools->doesFileExist(string("cpy_test.json")));
    EXPECT_TRUE(i_orchestration_tools->removeFile(string("cpy_test.json")));
    EXPECT_FALSE(i_orchestration_tools->doesFileExist(string("cpy_test.json")));

    EXPECT_FALSE(i_orchestration_tools->removeFile(string("test.json")));
}

TEST_F(OrchestrationToolsTest, jsonObjectSplitter)
{
    string update_text =    "{"
                            "   \"manifest\":"
                            "       {"
                            "           \"checksaum\":\"12e307c8f0aab4f51a160d5fb2396de1ca9da5b9\","
                            "           \"download-options\": ["
                            "               \"http://172.23.92.135/manifest_file.txt\""
                            "            ]"
                            "        },"
                            "    \"policy\":"
                            "       {"
                            "          \"checksum\":\"82e307c8f0aab4f51a160d5fb2396de1ca9da5b9\","
                            "          \"download-opations\": ["
                            "             \"http://172.23.92.135/policy_file.txt\","
                            "             \"ftp://172.23.92.135/policy_file.txt\""
                            "           ]"
                            "       },"
                            "    \"version\": \"10\""
                            "}";

    string manifest =   "{"
                        "           \"checksaum\":\"12e307c8f0aab4f51a160d5fb2396de1ca9da5b9\","
                        "           \"download-options\": ["
                        "               \"http://172.23.92.135/manifest_file.txt\""
                        "            ]"
                        "        }";

    string policy = "{"
                    "          \"checksum\":\"82e307c8f0aab4f51a160d5fb2396de1ca9da5b9\","
                    "          \"download-opations\": ["
                    "             \"http://172.23.92.135/policy_file.txt\","
                    "             \"ftp://172.23.92.135/policy_file.txt\""
                    "           ]"
                    "       }";

    Maybe<map<string, string>> parsed = i_orchestration_tools->jsonObjectSplitter(update_text, "", "");
    EXPECT_TRUE(parsed.ok());
    cleanSpaces(manifest);
    EXPECT_EQ(manifest, parsed.unpack().find("manifest")->second);
    cleanSpaces(policy);
    EXPECT_EQ(policy, parsed.unpack().find("policy")->second);
    string policy_value = parsed.unpack().find("policy")->second;
    EXPECT_TRUE(policy_value.find("82e307c8f0aab4f51a160d5fb2396de1ca9da5b9") != string::npos);

    string invalid_json =    "{"
                                "   \"manifest\":"
                                "       {"
                                "           \"checksaum\":\"12e307c8f0aab4f51a160d5fb2396de1ca9da5b9\","
                                "           \"download-options\": ["
                                "               \"http://172.23.92.135/manifest_file.txt\""
                                "            ]";
    parsed = i_orchestration_tools->jsonObjectSplitter(invalid_json, "", "");
    EXPECT_FALSE(parsed.ok());
}

TEST_F(OrchestrationToolsTest, jsonFileToPackages)
{
    stringstream string_stream;
    string_stream <<    "{"
                        "    \"packages\": ["
                        "        {"
                        "            \"download-path\": \"https://a/install_orchestration.sh\","
                        "            \"relative-path\": \"/install_orchestration.sh\","
                        "            \"name\": \"nano-agent\","
                        "            \"version\": \"24452\","
                        "            \"checksum-type\": \"sha1sum\","
                        "            \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
                        "            \"package-type\": \"service\","
                        "            \"require\": []"
                        "        }"
                        "    ]"
                        "}";
    i_orchestration_tools->writeFile(string_stream.str(), "packages_tmp.json");
    Maybe<map<string, Package>> packages = i_orchestration_tools->loadPackagesFromJson("packages_tmp.json");
    EXPECT_TRUE(packages.ok());
    EXPECT_TRUE(packages.unpack().find("nano-agent") != packages.unpack().end());
}

TEST_F(OrchestrationToolsTest, packagesToJsonFile)
{
    stringstream string_stream;
    string_stream <<   "{"
                        "   \"packages\": ["
                        "       {"
                        "           \"download-path\": \"https://a/install_orchestration.sh\","
                        "           \"relative-path\": \"/install_orchestration.sh\","
                        "           \"name\": \"my\","
                        "           \"version\": \"c\","
                        "           \"checksum-type\": \"sha1sum\","
                        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
                        "           \"package-type\": \"service\","
                        "           \"require\": []"
                        "       }"
                        "   ]"
                        "}";
    i_orchestration_tools->writeFile(string_stream.str(), "packages.json");
    Maybe<map<string, Package>> packages = i_orchestration_tools->loadPackagesFromJson("packages.json");
    EXPECT_TRUE(packages.ok());
    EXPECT_TRUE(i_orchestration_tools->packagesToJsonFile(packages.unpack(), "packages.json"));
    auto file_content = i_orchestration_tools->readFile("packages.json").unpack();
    EXPECT_TRUE(file_content.find("a58bbab8020b0e6d08568714b5e582a3adf9c805") != string::npos);
}

TEST_F(OrchestrationToolsTest, executeCommand)
{
    EXPECT_TRUE(i_orchestration_tools->executeCmd("exit 0"));
    EXPECT_FALSE(i_orchestration_tools->executeCmd("exit 1"));
}

TEST_F(OrchestrationToolsTest, createDirectory)
{
    string path = "/tmp/temp_dir";
    EXPECT_TRUE(i_orchestration_tools->createDirectory(path));
    EXPECT_TRUE(i_orchestration_tools->doesDirectoryExist(path));
    // get True after the directory already exists
    EXPECT_TRUE(i_orchestration_tools->createDirectory(path));
}

TEST_F(OrchestrationToolsTest, base64DecodeEncode)
{
    string clear_text = "{\n"
                        "   \"token\": \"77f380c5-9397-4e53-bb78-7c9df8f80a03\",\n"
                        "   \"expired\": false\n"
                        "}";
    string base64_text = "ewogICAidG9rZW4iOiAiNzdmMzgwYzUtOTM5Ny00ZTUzLWJiNzgtN2M5Z"\
                            "GY4ZjgwYTAzIiwKICAgImV4cGlyZWQiOiBmYWxzZQp9";
    EXPECT_EQ(clear_text, i_orchestration_tools->base64Decode(base64_text));
    EXPECT_EQ(base64_text, i_orchestration_tools->base64Encode(clear_text));

    string test_str = "";
    EXPECT_EQ(test_str, i_orchestration_tools->base64Decode(i_orchestration_tools->base64Encode(test_str)));
    test_str = "TEStsr fassaf saf";
    EXPECT_EQ(test_str, i_orchestration_tools->base64Decode(i_orchestration_tools->base64Encode(test_str)));
    test_str = "T24122142sfsavs!@!%";
    EXPECT_EQ(test_str, i_orchestration_tools->base64Decode(i_orchestration_tools->base64Encode(test_str)));
    test_str = "\nsdlsakdsad\nsdaslds";
    EXPECT_EQ(test_str, i_orchestration_tools->base64Decode(i_orchestration_tools->base64Encode(test_str)));
}
