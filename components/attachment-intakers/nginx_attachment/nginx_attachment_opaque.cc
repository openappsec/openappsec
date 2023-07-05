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

#include "nginx_attachment_opaque.h"

#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"

#include "config.h"
#include "virtual_modifiers.h"

using namespace std;
using namespace boost::uuids;

USE_DEBUG_FLAG(D_HTTP_MANAGER);

NginxAttachmentOpaque::NginxAttachmentOpaque(HttpTransactionData _transaction_data)
        :
    TableOpaqueSerialize<NginxAttachmentOpaque>(this),
    transaction_data(move(_transaction_data)),
    ctx(),
    session_tenant(),
    session_profile(),
    uuid()
{
    try {
        uuid = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_HTTP_MANAGER) << "Failed to generate UUID. Error: " << e.what();
    }

    dbgTrace(D_HTTP_MANAGER) << "Creating nginx opaque environment from: " << transaction_data;

    response_compression_stream = initCompressionStream();

    auto client_ip = transaction_data.getSourceIP();
    std::stringstream client_ip_str;
    client_ip_str << client_ip;
    setSourceIdentifier("sourceip", client_ip_str.str());

    ctx.registerValue("eventReferenceId", uuid, EnvKeyAttr::LogSection::DATA);
    ctx.registerValue<string>(HttpTransactionData::http_proto_ctx, transaction_data.getHttpProtocol());
    ctx.registerValue<string>(HttpTransactionData::method_ctx, transaction_data.getHttpMethod());
    ctx.registerValue<string>(HttpTransactionData::host_name_ctx, transaction_data.getParsedHost());
    ctx.registerValue<uint16_t>(HttpTransactionData::listening_port_ctx, transaction_data.getListeningPort());
    ctx.registerValue<IPAddr>(HttpTransactionData::listening_ip_ctx, transaction_data.getListeningIP());
    ctx.registerValue<IPAddr>(HttpTransactionData::client_ip_ctx, transaction_data.getSourceIP());
    ctx.registerValue<uint16_t>(HttpTransactionData::client_port_ctx, transaction_data.getSourcePort());
    ctx.registerFunc<string>(HttpTransactionData::source_identifier, [this](){ return source_identifier; });

    ctx.registerValue<string>(HttpTransactionData::uri_ctx, transaction_data.getParsedURI());
    auto decoder = makeVirtualContainer<HexDecoder<'%'>>(transaction_data.getURI());
    string decoded_url(decoder.begin(), decoder.end());
    auto question_mark_location = decoded_url.find('?');
    if (question_mark_location != string::npos && (question_mark_location + 1) <= decoded_url.size()) {
        ctx.registerValue(HttpTransactionData::uri_query_decoded, decoded_url.substr(question_mark_location + 1));
    }
    ctx.registerValue(HttpTransactionData::uri_path_decoded, decoded_url);
}

NginxAttachmentOpaque::~NginxAttachmentOpaque()
{
    finiCompressionStream(response_compression_stream);
}

// LCOV_EXCL_START - sync functions, can only be tested once the sync module exists
std::unique_ptr<TableOpaqueBase>
NginxAttachmentOpaque::prototype()
{
    return make_unique<NginxAttachmentOpaque>(HttpTransactionData());
}
// LCOV_EXCL_STOP

void
NginxAttachmentOpaque::setSessionTenantAndProfile(const string &tenant, const string &profile)
{
    session_tenant = tenant;
    session_profile = profile;
    Singleton::Consume<I_Environment>::by<NginxAttachmentOpaque>()->setActiveTenantAndProfile(
        session_tenant,
        session_profile
    );
}

void
NginxAttachmentOpaque::setSourceIdentifier(const string &header_key, const string &new_source_identifier)
{
    identifier_type = header_key;
    source_identifier = new_source_identifier;
}

const string &
NginxAttachmentOpaque::getSourceIdentifiersType() const
{
    return identifier_type;
}

void
NginxAttachmentOpaque::addToSavedData(const string &name, const string &data)
{
    saved_data[name] += data;
    ctx.registerValue(name, saved_data[name]);
}

void
NginxAttachmentOpaque::setSavedData(const string &name, const string &data, EnvKeyAttr::LogSection log_ctx)
{
    saved_data[name] = data;
    ctx.registerValue(name, data, log_ctx);
}
