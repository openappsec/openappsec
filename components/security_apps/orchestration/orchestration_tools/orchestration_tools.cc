// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "orchestration_tools.h"

#include "openssl/md5.h"
#include "openssl/sha.h"
#include "cereal/external/rapidjson/document.h"
#include "cereal/types/vector.hpp"
#include "cereal/types/set.hpp"
#include "agent_core_utilities.h"
#include "namespace_data.h"

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>

using namespace std;
using namespace rapidjson;

static const string base64_base_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const string ls_prefix = "ls ";
static const string extract_tenant_profile_suffix =
    "| grep tenant "
    "| cut -d '_' -f 2,4 "
    "| sort --unique "
    "| awk -F '_' '{ printf \"%s %s \",$1,$2 }'";

class OrchestrationTools::Impl : Singleton::Provide<I_OrchestrationTools>::From<OrchestrationTools>
{
public:
    bool packagesToJsonFile(const map<packageName, Package> &packages, const string &path) const override;
    Maybe<map<packageName, Package>> loadPackagesFromJson(const string &path) const override;

    Maybe<map<packageName, packageDetails>>
    jsonObjectSplitter(
        const string &json,
        const string &tenant_id,
        const string &profile_id) const override;

    shared_ptr<ifstream> fileStreamWrapper(const std::string &path) const override;
    Maybe<string> readFile(const string &path) const override;
    bool writeFile(const string &text, const string &path, bool append_mode = false) const override;
    bool removeFile(const string &path) const override;
    bool copyFile(const string &src_path, const string &dst_path) const override;
    bool doesFileExist(const string &file_path) const override;
    void getClusterId() const override;
    void fillKeyInJson(const string &filename, const string &_key, const string &_val) const override;
    bool createDirectory(const string &directory_path) const override;
    bool doesDirectoryExist(const string &dir_path) const override;
    bool executeCmd(const string &cmd) const override;
    bool isNonEmptyFile(const string &path) const override;
    void loadTenantsFromDir(const string &dir_path) const override;
    bool removeDirectory(const string &path, bool delete_content) const override;
    void deleteVirtualTenantProfileFiles(
        const std::string &tenant_id,
        const std::string &profile_id,
        const std::string &conf_path) const override;

    Maybe<string> calculateChecksum(Package::ChecksumTypes checksum_type, const string &path) const override;

    string base64Encode(const string &input) const override;
    string base64Decode(const string &input) const override;

private:
    string calculateFileMd5(ifstream &file) const;
    string calculateSHA256Sum(ifstream &file) const;
    string calculateSHA1Sum(ifstream &file) const;
    string calculateSHA512Sum(ifstream &file) const;
};

using packageName = I_OrchestrationTools::packageName;
using packageDetails = I_OrchestrationTools::packageDetails;

static bool
checkExistence(const string &path, bool is_dir)
{
    try {
        struct stat info;
        if (stat(path.c_str(), &info) != 0) return false;
        int flag = is_dir ? S_IFDIR : S_IFREG;
        return info.st_mode & flag;
    } catch (exception &e) {
        return false;
    }
}

// LCOV_EXCL_START Reason: NSaaS upgrade WA
void
OrchestrationTools::Impl::fillKeyInJson(const string &filename, const string &_key, const string &_val) const
{
    // Load the JSON file into a string
    std::ifstream ifs(filename);
    std::string jsonStr((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

    dbgTrace(D_ORCHESTRATOR) << "Trying to parse " << filename;
    // Parse the JSON string
    Document doc;
    doc.Parse(jsonStr.c_str());

    // Check if the key exists
    if (doc.HasMember(_key.c_str())) {
        dbgTrace(D_ORCHESTRATOR) << _key << " already exists.";
        return;
    }

    // Add the  key with value
    Value key(_key.c_str(), doc.GetAllocator());
    Value val(_val.c_str(), doc.GetAllocator());
    doc.AddMember(key, val, doc.GetAllocator());

    // Write the modified JSON to a new file
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    doc.Accept(writer);
    std::ofstream ofs(filename);
    ofs << buffer.GetString() << std::endl;

    dbgTrace(D_ORCHESTRATOR) << _key << " added with val " << _val;
}
// LCOV_EXCL_STOP

bool
isPlaygroundEnv()
{
    const char *env_string = getenv("PLAYGROUND");

    if (env_string == nullptr) return false;
    string env_value = env_string;
    transform(env_value.begin(), env_value.end(), env_value.begin(), ::tolower);

    return env_value == "true";
}

Maybe<NamespaceData, string>
getNamespaceDataFromCluster(const string &path)
{
    NamespaceData name_space;
    string token = Singleton::Consume<I_EnvDetails>::by<OrchestrationTools>()->getToken();
    Flags<MessageConnConfig> conn_flags;
    conn_flags.setFlag(MessageConnConfig::SECURE_CONN);
    conn_flags.setFlag(MessageConnConfig::IGNORE_SSL_VALIDATION);
    auto messaging = Singleton::Consume<I_Messaging>::by<OrchestrationTools>();
    bool res = messaging->sendObject(
        name_space,
        I_Messaging::Method::GET,
        "kubernetes.default.svc",
        443,
        conn_flags,
        path,
        "Authorization: Bearer " + token + "\nConnection: close"
    );

    if (res) return name_space;

    return genError(string("Was not able to get object form k8s cluser in path: " + path));
}

bool
doesClusterIdExists()
{
    string playground_uid = isPlaygroundEnv() ? "playground-" : "";

    dbgTrace(D_ORCHESTRATOR) << "Getting cluster UID";

    auto maybe_namespaces_data = getNamespaceDataFromCluster("/api/v1/namespaces/");

    if (!maybe_namespaces_data.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to retrieve K8S namespace data. Error: "
            << maybe_namespaces_data.getErr();
        return false;
    }

    NamespaceData namespaces_data = maybe_namespaces_data.unpack();

    Maybe<string> maybe_ns_uid = namespaces_data.getNamespaceUidByName("kube-system");
    if (!maybe_ns_uid.ok()) {
        dbgWarning(D_ORCHESTRATOR) << maybe_ns_uid.getErr();
        return false;
    }
    string uid = playground_uid + maybe_ns_uid.unpack();
    dbgTrace(D_ORCHESTRATOR) << "Found k8s cluster UID: " << uid;
    I_Environment *env = Singleton::Consume<I_Environment>::by<OrchestrationTools>();
    env->getConfigurationContext().registerValue<string>(
        "k8sClusterId",
        uid,
        EnvKeyAttr::LogSection::SOURCE
    );
    I_AgentDetails *i_agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationTools>();
    i_agent_details->setClusterId(uid);
    return true;
}

void
OrchestrationTools::Impl::getClusterId() const
{
    auto env_type = Singleton::Consume<I_EnvDetails>::by<OrchestrationTools>()->getEnvType();

    if (env_type == EnvType::K8S) {
        Singleton::Consume<I_MainLoop>::by<OrchestrationTools>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::Offline,
            [this] ()
            {
                while(!doesClusterIdExists()) {
                    Singleton::Consume<I_MainLoop>::by<OrchestrationTools>()->yield(chrono::seconds(1));
                }
                return;
            },
            "Get k8s cluster ID"
        );
    }
}

bool
OrchestrationTools::Impl::doesFileExist(const string &file_path) const
{
    return checkExistence(file_path, false);
}

bool
OrchestrationTools::Impl::doesDirectoryExist(const string &dir_path) const
{
    return checkExistence(dir_path, true);
}

bool
OrchestrationTools::Impl::writeFile(const string &text, const string &path, bool append_mode) const
{
    dbgDebug(D_ORCHESTRATOR) << "Writing file: text = " << text << ", path = " << path;
    if (path.find('/') != string::npos) {
        string dir_path = path.substr(0, path.find_last_of('/'));
        if (!createDirectory(dir_path)) {
            dbgDebug(D_ORCHESTRATOR) << "Failed to write file because directory creation failed. file: "
                    << path;
            return false;
        }
    }

    ofstream fout;

    if (append_mode) {
        fout.open(path, std::ios::app);
    } else {
        fout.open(path);
    }
    try {
        fout << text;
        return true;
    } catch (const ofstream::failure &e) {
        dbgDebug(D_ORCHESTRATOR) << "Error while writing file in " << path << ", " << e.what();
    }
    return false;
}

bool
OrchestrationTools::Impl::isNonEmptyFile(const string &path) const
{
    if (!doesFileExist(path)) {
        dbgDebug(D_ORCHESTRATOR) << "Cannot read file, file does not exist. File: " << path;
        return false;
    }

    try {
        ifstream text_file(path);
        if (!text_file) {
            dbgDebug(D_ORCHESTRATOR) << "Cannot open file. File: " << path;
            return false;
        }

        char buf[1];
        text_file.read(buf, 1);
        return text_file.gcount() != 0;
    } catch (const ifstream::failure &e) {
        dbgDebug(D_ORCHESTRATOR) << "Error while reading file " << path << ", " << e.what();
    }

    return false;
}

shared_ptr<ifstream>
OrchestrationTools::Impl::fileStreamWrapper(const std::string &path) const
{
    return make_shared<ifstream>(path);
}

Maybe<string>
OrchestrationTools::Impl::readFile(const string &path) const
{
    if (!doesFileExist(path)) {
        dbgDebug(D_ORCHESTRATOR) << "Cannot read file, file does not exist. File: " << path;
        return genError("File " + path + " does not exist.");
    }
    try {
        ifstream text_file(path);
        if (!text_file) {
            return genError("Cannot open file. File: " + path);
        }
        stringstream buffer;
        buffer << text_file.rdbuf();
        return buffer.str();
    } catch (const ifstream::failure &e) {
        dbgDebug(D_ORCHESTRATOR) << "Error while reading file " << path << ", " << e.what();
        return genError("Error while reading file " + path + ", " + e.what());
    }
}

bool
OrchestrationTools::Impl::removeFile(const string &path) const
{
    if (remove(path.c_str()) != 0) {
        dbgDebug(D_ORCHESTRATOR) << "Error deleting file. File: " << path;
        return false;
    } else {
        dbgDebug(D_ORCHESTRATOR) << "Successfully deleted the file " << path;
    }
    return true;
}

bool
OrchestrationTools::Impl::removeDirectory(const string &path, bool delete_content) const
{
    if (!NGEN::Filesystem::deleteDirectory(path, delete_content)) {
        dbgDebug(D_ORCHESTRATOR) << "Deletion of the folder at path " << path << " failed.";
        return false;
    }
    dbgDebug(D_ORCHESTRATOR) << "Successfully deleted folder at path " << path;
    return true;
}

void
OrchestrationTools::Impl::deleteVirtualTenantProfileFiles(
    const string &tenant_id,
    const string &profile_id,
    const string &conf_path) const
{
    string tenant_and_profile_suffix = "tenant_" + tenant_id + "_profile_" + profile_id;
    string virtual_policy_dir = conf_path + "/" + tenant_and_profile_suffix;
    if (!removeDirectory(virtual_policy_dir, true)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to delete virtual policy folder : " << virtual_policy_dir;
    } else {
        dbgDebug(D_ORCHESTRATOR) << "Virtual policy folder " << virtual_policy_dir << " deleted successfully.";
    }

    string settings_file_path = virtual_policy_dir + "_settings.json";
    if (!removeFile(settings_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to delete virtual policy settings file : " << settings_file_path;
    } else {
        dbgDebug(D_ORCHESTRATOR) << "Virtual policy settings file " << settings_file_path << " deleted successfully.";
    }
}

void
OrchestrationTools::Impl::loadTenantsFromDir(const string &dir_path) const
{
    dbgTrace(D_ORCHESTRATOR) << "Load existing tenants and profiles from the configuration folder";

    string shell_cmd_string = ls_prefix + dir_path + extract_tenant_profile_suffix;
    auto shell = Singleton::Consume<I_ShellCmd>::by<OrchestrationTools>();
    Maybe<string> output_res = shell->getExecOutput(shell_cmd_string);

    if (!output_res.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to load existing tenants from configuration folder: " + output_res.getErr();
        return;
    }

    auto tenant_manager = Singleton::Consume<I_TenantManager>::by<OrchestrationTools>();
    stringstream ss(output_res.unpack());
    string tenant_id;
    string profile_id;
    while (!ss.eof() && getline(ss, tenant_id, ' ') && !ss.eof() && getline(ss, profile_id, ' ')) {
        dbgTrace(D_ORCHESTRATOR) << "Add existing tenant_" + tenant_id + "_profile_" + profile_id;
        tenant_manager->addActiveTenantAndProfile(tenant_id, profile_id);
    }
}

Maybe<string>
OrchestrationTools::Impl::calculateChecksum(Package::ChecksumTypes checksum_type, const string &path) const
{
    if (!doesFileExist(path)) {
        dbgDebug(D_ORCHESTRATOR) << "Cannot read file, file does not exist. File: " << path;
        return genError("File " + path + " does not exist.");
    }
    try {
        ifstream file(path);
        if (!file) {
            return genError("Cannot open file. File: " + path);
        }

        switch (checksum_type) {
            case Package::ChecksumTypes::MD5:
                return calculateFileMd5(file);
            case Package::ChecksumTypes::SHA256:
                return calculateSHA256Sum(file);
            case Package::ChecksumTypes::SHA1:
                return calculateSHA1Sum(file);
            case Package::ChecksumTypes::SHA512:
                return calculateSHA512Sum(file);
        }
    } catch (const ifstream::failure &e) {
        dbgDebug(D_ORCHESTRATOR) << "Error while reading file " << path << ", " << e.what();
        return genError("Error while reading file " + path + ", " + e.what());
    }

    dbgAssert(false) << "Checksum type is not supported. Checksum type: " << static_cast<unsigned int>(checksum_type);
    return genError("Unsupported checksum type");
}

bool
OrchestrationTools::Impl::copyFile(const string &src_path, const string &dst_path) const
{
    if (!doesFileExist(src_path)) {
        dbgDebug(D_ORCHESTRATOR) << "Failed to copy file. File does not exist: " << src_path;
        return false;
    }

    if (src_path.compare(dst_path) == 0) {
        dbgDebug(D_ORCHESTRATOR) << "Source path is equal to the destination path. Path: " << src_path;
        return true;
    }

    if (dst_path.find('/') != string::npos) {
        string dir_path = dst_path.substr(0, dst_path.find_last_of('/'));
        if (!createDirectory(dir_path)) {
            dbgDebug(D_ORCHESTRATOR) << "Failed to copy file. Directory creation failed: " << dir_path;
            return false;
        }
    }

    try {
        ifstream src(src_path, ios::binary);
        ofstream dest(dst_path, ios::binary);
        dest << src.rdbuf();
        return true;
    } catch (const ios_base::failure &e) {
        dbgDebug(D_ORCHESTRATOR) << "Failed to copy file "  << src_path << " to " << dst_path << ", " << e.what();
    }
    return false;
}

Maybe<map<packageName, packageDetails>>
OrchestrationTools::Impl::jsonObjectSplitter(
    const string &json,
    const string &tenant_id,
    const string &profile_id) const
{
    Document document;
    map<string, string> parsed;

    document.Parse(json.c_str());
    if (document.HasParseError()) return genError("JSON file is not valid.");

    for (Value::MemberIterator itr = document.MemberBegin(); itr != document.MemberEnd(); ++itr) {
        if (!tenant_id.empty() && itr->value.IsObject()) {
            itr->value.AddMember(
                Value("tenantID"),
                Value(tenant_id.c_str(), tenant_id.size()),
                document.GetAllocator()
            );

            itr->value.AddMember(
                Value("profileID"),
                Value(profile_id.c_str(), profile_id.size()),
                document.GetAllocator()
            );
        }

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        itr->value.Accept(writer);
        parsed.insert({itr->name.GetString(), buffer.GetString()});
    }
    return parsed;
}

bool
OrchestrationTools::Impl::packagesToJsonFile(const map<packageName, Package> &packages, const string &path) const
{
    try {
        ofstream os(path);
        cereal::JSONOutputArchive archive_out(os);
        vector<Package> packges_vector;
        for (auto p: packages) {
            packges_vector.push_back(p.second);
        }
        archive_out(cereal::make_nvp("packages", packges_vector));
    } catch (cereal::Exception &e) {
        dbgDebug(D_ORCHESTRATOR) << "Failed to write vector of packages to JSON file " << path << ", " << e.what();
        return false;
    }
    return true;
}

Maybe<map<packageName, Package>>
OrchestrationTools::Impl::loadPackagesFromJson(const string &path) const
{
    dbgDebug(D_ORCHESTRATOR) << "Parsing packages from " << path;
    try {
        ifstream is(path);
        cereal::JSONInputArchive archive_in(is);
        vector<Package> packages_vector;
        archive_in(packages_vector);
        map<packageName, Package> packages;
        for (auto p: packages_vector) {
            packages[p.getName()] = p;
        }
        return packages;
    } catch (const exception &e) {
        dbgDebug(D_ORCHESTRATOR) << "Failed to load vector of packages from JSON file " << path << ", " << e.what();
        return genError(e.what());
    }
}

bool
OrchestrationTools::Impl::createDirectory(const string &directory_path) const
{
    string dir;
    struct stat info;
    for (size_t i = 0; i < directory_path.size(); i++) {
        dir.push_back(directory_path[i]);
        if (directory_path[i] == '/' || i + 1 == directory_path.size()) {
            if (stat(dir.c_str(), &info) != 0) {
                if(mkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
                    dbgDebug(D_ORCHESTRATOR) << "Failed to create directory " << directory_path;
                    return false;
                }
            }
        }
    }
    return true;
}

bool
OrchestrationTools::Impl::executeCmd(const string &cmd) const
{
    int ret = system(cmd.c_str());
    if (ret != 0) {
        dbgDebug(D_ORCHESTRATOR) << "System command failed, " + cmd;
        return false;
    }
    return true;
}

string
OrchestrationTools::Impl::calculateFileMd5(ifstream &file) const
{
    MD5_CTX md5_Context;
    MD5_Init(&md5_Context);

    char read_buf[512];
    while (file) {
        file.read(read_buf, 512);
        auto size = file.gcount();
        if (!size) break;
        MD5_Update(&md5_Context, read_buf, size);
    }

    unsigned char digest[16];
    MD5_Final(digest, &md5_Context);

    stringstream out;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        out << setfill('0') << setw(2) << hex << (unsigned int)digest[i];
    }
    return out.str();
}

string
OrchestrationTools::Impl::calculateSHA256Sum(ifstream &file) const
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char read_buf[512];
    while (file) {
        file.read(read_buf, 512);
        auto size = file.gcount();
        if (!size) break;
        SHA256_Update(&sha256, read_buf, size);
    }

    SHA256_Final(hash, &sha256);
    stringstream string_stream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        string_stream << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return string_stream.str();
}

string
OrchestrationTools::Impl::calculateSHA1Sum(ifstream &file) const
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1;
    SHA1_Init(&sha1);

    char read_buf[512];
    while (file) {
        file.read(read_buf, 512);
        auto size = file.gcount();
        if (!size) break;
        SHA1_Update(&sha1, read_buf, size);
    }

    SHA1_Final(hash, &sha1);
    stringstream string_stream;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        string_stream << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return string_stream.str();
}

string
OrchestrationTools::Impl::calculateSHA512Sum(ifstream &file) const
{
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);

    char read_buf[512];
    while (file) {
        file.read(read_buf, 512);
        auto size = file.gcount();
        if (!size) break;
        SHA512_Update(&sha512, read_buf, size);
    }

    SHA512_Final(hash, &sha512);
    stringstream string_stream;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        string_stream << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return string_stream.str();
}

string
OrchestrationTools::Impl::base64Encode(const string &input) const
{
    string out;
    int val = 0, val_base = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        val_base += 8;
        while (val_base >= 0) {
            out.push_back(base64_base_str[(val >> val_base) & 0x3F]);
            val_base -= 6;
        }
    }
    // -6 indicates the number of bits to take from each character
    // (6 bits is enough to present a range of 0 to 63)
    if (val_base > -6) out.push_back(base64_base_str[((val << 8) >> (val_base + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

string
OrchestrationTools::Impl::base64Decode(const string &input) const
{
    string out;
    vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) {
        T[base64_base_str[i]] = i;
    }

    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

OrchestrationTools::OrchestrationTools() : Component("OrchestrationTools"), pimpl(make_unique<Impl>()) {}

OrchestrationTools::~OrchestrationTools() {}
