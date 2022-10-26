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

#include "user_identifiers_config.h"

#include "buffer.h"
#include "nginx_attachment.h"
#include "nginx_attachment_opaque.h"
#include "nginx_parser.h"
#include "cidrs_data.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_ATTACHMENT_PARSER);

static const Buffer header_key("headerkey", 9, Buffer::MemoryType::STATIC);
static const Buffer jwt("authorization", 13, Buffer::MemoryType::STATIC);
static const Buffer xff("x-forwarded-for", 15, Buffer::MemoryType::STATIC);
static const Buffer cookie("cookie", 6, Buffer::MemoryType::STATIC);
static const Buffer source_ip("sourceip", 8, Buffer::MemoryType::STATIC);
static const Buffer oauth("_oauth2_proxy", 13, Buffer::MemoryType::STATIC);
static const Buffer empty_buffer("", 0, Buffer::MemoryType::STATIC);

const static string jwt_prefix = "Bearer ";

UsersAllIdentifiersConfig::UsersIdentifiersConfig::UsersIdentifiersConfig() : source_identifier(source_ip){};

UsersAllIdentifiersConfig::UsersIdentifiersConfig::UsersIdentifiersConfig(const std::string &identifier)
        :
    source_identifier(identifier)
{}

bool
UsersAllIdentifiersConfig::UsersIdentifiersConfig::operator==(const UsersIdentifiersConfig &other) const
{
    return source_identifier == other.source_identifier;
}

void
UsersAllIdentifiersConfig::UsersIdentifiersConfig::load(cereal::JSONInputArchive &ar)
{
    parseJSONKey<string>("sourceIdentifier", source_identifier, ar);
    parseJSONKey<vector<string>>("identifierValues", identifier_values, ar);
}

bool
UsersAllIdentifiersConfig::UsersIdentifiersConfig::isEqualSourceIdentifier(const string &other) const
{
    if (source_identifier.size() != other.size()) return false;
    return equal(
        source_identifier.begin(),
        source_identifier.end(),
        other.begin(),
        [] (char c1, char c2) { return tolower(c1) == tolower(c2); }
    );
}

UsersAllIdentifiersConfig::UsersAllIdentifiersConfig()
{
}

vector<string>
UsersAllIdentifiersConfig::getHeaderValuesFromConfig(const string &header_key) const
{
    for (auto user_identifier : user_identifiers) {
        if (user_identifier.isEqualSourceIdentifier(header_key)) {
            dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Match source identifier is found";
            return user_identifier.getIdentifierValues();
        }
    }
    return vector<string>();
}

void
UsersAllIdentifiersConfig::load(cereal::JSONInputArchive &ar)
{
    vector<UsersIdentifiersConfig> tmp_user_identifiers;
    parseJSONKey<vector<UsersIdentifiersConfig>>("sourceIdentifiers", tmp_user_identifiers, ar);

    user_identifiers.clear();
    user_identifiers.reserve(tmp_user_identifiers.size() + 1);
    for (auto &identifier : tmp_user_identifiers) {
        if (identifier.getSourceIdentifier() == header_key) {
            for (const auto &header : identifier.getIdentifierValues()) {
                user_identifiers.emplace_back(header);
            }
        } else {
            user_identifiers.push_back(identifier);
        }
    }

    vector<UsersIdentifiersConfig> default_order = {
        UsersIdentifiersConfig(cookie),
        UsersIdentifiersConfig(jwt),
        UsersIdentifiersConfig(xff)
    };

    auto last_user_defined_header = find_first_of(
        default_order.rbegin(),
        default_order.rend(),
        user_identifiers.begin(),
        user_identifiers.end()
    );
    if (last_user_defined_header == default_order.rend()) {
        user_identifiers.insert(user_identifiers.end(), default_order.begin(), default_order.end());
    } else {
        auto last_defined_forwards = find(default_order.begin(), default_order.end(), *last_user_defined_header);
        user_identifiers.insert(user_identifiers.end(), last_defined_forwards + 1, default_order.end());
    }
}

static bool
compareBufferWithoutCase(const Buffer &b1, const Buffer &b2)
{
    if (b1.size() != b2.size()) return false;
    return equal(b1.begin(), b1.end(), b2.begin(), [] (u_char c1, u_char c2) { return tolower(c1) == tolower(c2); });
}

void
UsersAllIdentifiersConfig::setIdentifierTopaqueCtx(const HttpHeader &header) const
{
    if (compareBufferWithoutCase(jwt, header.getKey())) {
        setJWTValuesToOpaqueCtx(header);
    } else if (compareBufferWithoutCase(xff, header.getKey())) {
        setXFFValuesToOpaqueCtx(header, ExtractType::SOURCEIDENTIFIER);
    } else if (compareBufferWithoutCase(cookie, header.getKey())) {
        setCookieValuesToOpaqueCtx(header);
    } else {
        setCustomHeaderToOpaqueCtx(header);
    }
}

bool
UsersAllIdentifiersConfig::isHigherPriority(const string &current_identifier, const string &header_key) const
{
    for (auto user_identifier : user_identifiers) {
        if (user_identifier.isEqualSourceIdentifier(current_identifier)) return false;
        if (user_identifier.isEqualSourceIdentifier(header_key)) return true;
    }
    return false;
}

void
UsersAllIdentifiersConfig::setJWTValuesToOpaqueCtx(const HttpHeader &header) const
{
    const vector<string> jwt_values = getHeaderValuesFromConfig(header.getKey());
    if (jwt_values.size() == 0) {
        dbgTrace(D_NGINX_ATTACHMENT_PARSER) << "No JWT keys exists in configuration";
        return;
    }
    if (bcmp(header.getValue().data(), jwt_prefix.c_str(), jwt_prefix.size()) != 0) {
        dbgTrace(D_NGINX_ATTACHMENT_PARSER) << "Invalid JWT header, 'Bearer' prefix missing";
        return;
    }
    int start_dot = -1;
    int end_dot = -1;
    for (uint i = 0 ; i < header.getValue().size() ; i++) {
        if (header.getValue()[i] == '.') {
            if (start_dot < 0) {
                start_dot = i;
            } else if (end_dot < 0) {
                end_dot = i;
            }
        }
    }
    if (start_dot < 0 || end_dot < 0) {
        dbgTrace(D_NGINX_ATTACHMENT_PARSER) << "The header does not contain dots";
        return;
    }

    string jwt_str(
        reinterpret_cast<const char *>(header.getValue().data()),
        start_dot + 1,
        end_dot - start_dot - 1
    );
    I_Encryptor *encryptor = Singleton::Consume<I_Encryptor>::by<NginxParser>();
    auto decoded_jwt = encryptor->base64Decode(jwt_str);
    dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Base64 decoded JWT: " << decoded_jwt;

    auto i_transaction_table = Singleton::Consume<I_TableSpecific<SessionID>>::by<NginxAttachment>();
    if (!i_transaction_table || !i_transaction_table->hasState<NginxAttachmentOpaque>()) {
        dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Can't get the transaction table";
        return;
    }
    NginxAttachmentOpaque &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
    stringstream ss;
    ss.str(decoded_jwt);
    cereal::JSONInputArchive in_ar(ss);
    for (const string &field_name : jwt_values) {
        try {
            string tmp_val;
            in_ar(cereal::make_nvp(field_name, tmp_val));
            opaque.setSourceIdentifier(header.getKey(), tmp_val);
            dbgDebug(D_NGINX_ATTACHMENT_PARSER)
                << "Added source identifir to context. Key: "
                << field_name
                << ". Value: "
                << tmp_val;
            return;
        } catch (const cereal::Exception &e) {
            dbgTrace(D_NGINX_ATTACHMENT_PARSER)
                << "Unable to find value for the key: "
                << field_name
                << ". Error: "
                << e.what();
        }
    }
}

static string
stripOptionalPort(const string::const_iterator &first, const string::const_iterator &last)
{
    // Microsoft XFF+IPv6+Port yikes - see also here https://github.com/eclipse/jetty.project/issues/3630
    if (*first == '[') {
        // Possible bracketed IPv6 address such as "[2001:db8::1]" + optional numeric ":<port>"
        auto close_bracket = find(first + 1, last, ']');
        if (close_bracket == last) return string(first, last);
        return string(first+1, close_bracket);
    }

    auto first_colon = find(first, last, ':');
    if (first_colon == last) return string(first, last);

    // If there is more than one colon it means its probably IPv6 address without brackets
    auto second_colon = find(first_colon + 1, last, ':');
    if (second_colon != last) return string(first, last);

    // If there's only one colon it can't be IPv6 and can only be IPv4 with port
    return string(first, first_colon);
}

static vector<string>
split(const string &str)
{
    vector<string> elems;
    elems.reserve(str.size() / 8 + 1);
    auto sub_start = str.cbegin(), sub_end = str.cbegin();
    for (auto iter = str.cbegin(); iter != str.cend(); ++iter) {
        if (isspace(*iter)) {
            if (sub_start == iter) {
                ++sub_start;
                ++sub_end;
            }
        } else if (*iter == ',') {
            if (sub_start != sub_end) {
                elems.push_back(stripOptionalPort(sub_start, sub_end));
            }
            sub_end = iter + 1;
            sub_start = iter + 1;
        } else {
            sub_end = iter + 1;
        }
    }

    if (sub_start != sub_end) {
        elems.push_back(stripOptionalPort(sub_start, sub_end));
    }

    return elems;
}

static bool
isIpTrusted(const string &value, const vector<CIDRSData> &cidr_values)
{
    if (cidr_values.empty()) return true;

    for(const auto &cidr_data : cidr_values) {
        if (cidr_data.contains(value)) return true;
    }

    return false;
}

Maybe<string>
UsersAllIdentifiersConfig::parseXForwardedFor(const string &str) const
{
    vector<string> header_values = split(str);

    if (header_values.empty()) return genError("No IP found in the xff header list");

    vector<string> xff_values = getHeaderValuesFromConfig("x-forwarded-for");
    vector<CIDRSData> cidr_values(xff_values.begin(), xff_values.end());

    for (const string &value : header_values) {
        if (!IPAddr::createIPAddr(value).ok()) {
            dbgWarning(D_NGINX_ATTACHMENT_PARSER) << "Invalid IP address found in the xff header IPs list: " << value;
            return genError("Invalid IP address");
        }
        if (!isIpTrusted(value, cidr_values)) return genError("Untrusted Ip found");
    }

    return header_values[0];
}


void
UsersAllIdentifiersConfig::setXFFValuesToOpaqueCtx(const HttpHeader &header, ExtractType type) const
{
    auto value = parseXForwardedFor(header.getValue());
    if (!value.ok()) {
        dbgTrace(D_NGINX_ATTACHMENT_PARSER) << "Could not extract source identifier from X-Forwarded-For header";
        return;
    };
    auto i_transaction_table = Singleton::Consume<I_TableSpecific<SessionID>>::by<NginxAttachment>();
    if (!i_transaction_table || !i_transaction_table->hasState<NginxAttachmentOpaque>()) {
        dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Can't get the transaction table";
        return;
    }
    NginxAttachmentOpaque &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
    if (type == ExtractType::SOURCEIDENTIFIER) {
        opaque.setSourceIdentifier(header.getKey(), value.unpack());
        dbgDebug(D_NGINX_ATTACHMENT_PARSER)
            << "Added source identifir to XFF "
            <<  value.unpack();
    } else {
        opaque.setSavedData(HttpTransactionData::proxy_ip_ctx, value.unpack());
    }
}

void
UsersAllIdentifiersConfig::setCustomHeaderToOpaqueCtx(const HttpHeader &header) const
{
    auto i_transaction_table = Singleton::Consume<I_TableSpecific<SessionID>>::by<NginxAttachment>();
    if (!i_transaction_table || !i_transaction_table->hasState<NginxAttachmentOpaque>()) {
        dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Can't get the transaction table";
        return;
    }
    i_transaction_table->getState<NginxAttachmentOpaque>().setSourceIdentifier(header.getKey(), header.getValue());
    dbgDebug(D_NGINX_ATTACHMENT_PARSER)
        << "Added source identifir to custom header: "
        <<  static_cast<string>(header.getValue());
    return;
}

Maybe<string>
UsersAllIdentifiersConfig::parseCookieElement(
    const string::const_iterator &start,
    const string::const_iterator &end,
    const string &key) const
{
    auto curr_pos = start;

    // Skip whitespace
    for (; curr_pos != end && isspace(*curr_pos); ++curr_pos);

    // Check key
    for (auto key_pos = key.begin(); key_pos != key.end(); ++key_pos) {
        if (curr_pos == end || tolower(*curr_pos) != tolower(*key_pos)) return genError("Key value not found");
        ++curr_pos;
    }

    // Skip whitespace
    for (; curr_pos != end && isspace(*curr_pos); ++curr_pos);

    // Check for '='
    if (curr_pos == end || *curr_pos != '=') return genError("Equal sign not found");
    ++curr_pos;

    // Skip whitespace
    for (; curr_pos != end && isspace(*curr_pos); ++curr_pos);

    auto value_start = curr_pos;

    // Read value
    for (; curr_pos != end && !isspace(*curr_pos); ++curr_pos);

    auto value_end = curr_pos;

    // Verify value read currectly - should be only whitespaces to the end;
    for (; curr_pos != end && isspace(*curr_pos); ++curr_pos);
    if (curr_pos != end) return genError("Unexpected characters when reading a value");

    return string(value_start, value_end);
}

Buffer
UsersAllIdentifiersConfig::extractKeyValueFromCookie(const string &cookie_value, const string &key) const
{
    auto curr_start = cookie_value.begin();
    auto end = cookie_value.end();

    while (curr_start != end) {
        auto curr_end = find(curr_start, end, ';');
        auto res = parseCookieElement(curr_start, curr_end, key);
        if (res.ok()) {
            if (key != oauth) return *res;
            I_Encryptor *encryptor = Singleton::Consume<I_Encryptor>::by<NginxParser>();
            auto decoded_value = encryptor->base64Decode(*res);
            auto decoded_end = find(decoded_value.begin(), decoded_value.end(), '|');
            return Buffer(string(decoded_value.begin(), decoded_end));
        }

        if (curr_end != end) ++curr_end;
        curr_start = curr_end;
    }

    return empty_buffer;
}

void
UsersAllIdentifiersConfig::setCookieValuesToOpaqueCtx(const HttpHeader &header) const
{
    vector<string> cookie_keys = getHeaderValuesFromConfig(header.getKey());
    cookie_keys.push_back(oauth);
    cookie_keys.push_back("jsessionid");
    for (const string &key : cookie_keys) {
        string value = extractKeyValueFromCookie(header.getValue(), key);
        if (!value.empty()) {
            dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Set source identifier from cookie: Oauth 2";
            auto i_transaction_table = Singleton::Consume<I_TableSpecific<SessionID>>::by<NginxAttachment>();
            if (!i_transaction_table || !i_transaction_table->hasState<NginxAttachmentOpaque>()) {
                dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Can't get the transaction table";
                return;
            }
            NginxAttachmentOpaque &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
            opaque.setSourceIdentifier(header.getKey(), value);
            return;
        }
    }
}

void
UsersAllIdentifiersConfig::parseRequestHeaders(const HttpHeader &header) const
{
    auto i_transaction_table = Singleton::Consume<I_TableSpecific<SessionID>>::by<NginxAttachment>();
    if (!i_transaction_table || !i_transaction_table->hasState<NginxAttachmentOpaque>()) {
        dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Can't get the transaction table";
        return;
    }

    NginxAttachmentOpaque &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
    const string &current_identifier = opaque.getSourceIdentifiersType();

    if (!isHigherPriority(current_identifier, header.getKey())) return;

    setIdentifierTopaqueCtx(header);
}
