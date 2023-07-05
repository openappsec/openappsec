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

#include "intelligence_is_v2/query_request_v2.h"
#include "debug.h"
#include "enum_array.h"

const uint QueryRequest::default_min_confidence = 500;
const uint QueryRequest::default_assets_limit = 20;

using namespace std;
using namespace Intelligence_IS_V2;

USE_DEBUG_FLAG(D_INTELLIGENCE);

static const EnumArray<ObjectType, string> object_type_to_string_array{ "asset", "zone", "configuration" };

BulkQueryRequest::BulkQueryRequest(QueryRequest &_request, int _index)
        :
    request(_request),
    index(_index)
{}

QueryRequest
BulkQueryRequest::getQueryRequest() const
{
    return request;
}

void
BulkQueryRequest::save(cereal::JSONOutputArchive &ar) const
{
    ar(
        cereal::make_nvp("query", getQueryRequest()),
        cereal::make_nvp("index",  index)
    );
}

QueryRequest::QueryRequest(
    Condition condition_type,
    const string &key,
    const string &value,
    bool full_reponse,
    AttributeKeyType attribute_type
) {
    query = SerializableQueryFilter(condition_type, createAttributeString(key, attribute_type), value);
    assets_limit = default_assets_limit;
    full_response = full_reponse;
}

QueryRequest::QueryRequest(
    Condition condition_type,
    const string &key,
    const int64_t &value,
    bool full_reponse,
    AttributeKeyType attribute_type
) {
    query = SerializableQueryFilter(condition_type, createAttributeString(key, attribute_type), value);
    assets_limit = default_assets_limit;
    full_response = full_reponse;
}

Maybe<string>
QueryRequest::convertObjectTypeToString() const
{
    if (!object_type.ok()) return object_type.passErr();
    if (static_cast<uint>(*object_type) < static_cast<uint>(ObjectType::COUNT)) {
        return object_type_to_string_array[*object_type];
    }

    return genError("Illegal Object Type.");
}

void
QueryRequest::saveToJson(cereal::JSONOutputArchive &ar) const
{
    ar(
        cereal::make_nvp("limit", assets_limit),
        cereal::make_nvp("fullResponse", full_response),
        cereal::make_nvp("query", query)
    );

    auto objTypeString = convertObjectTypeToString();
    if (objTypeString.ok()) {
        ar(cereal::make_nvp("objectType", *objTypeString));
    } else {
        dbgTrace(D_INTELLIGENCE) << objTypeString.getErr();
    }

    if (cursor.ok()) ar(cereal::make_nvp("cursor", cursor.unpack().second));
    requested_attributes.save(ar);
    query_types.save(ar);
}

void
QueryRequest::save(cereal::JSONOutputArchive &ar) const
{
    ar(
        cereal::make_nvp("limit", assets_limit),
        cereal::make_nvp("fullResponse", full_response),
        cereal::make_nvp("query", query)
    );

    auto objTypeString = convertObjectTypeToString();
    if (objTypeString.ok()) {
        ar(cereal::make_nvp("objectType", *objTypeString));
    } else {
        dbgTrace(D_INTELLIGENCE) << objTypeString.getErr();
    }

    if (cursor.ok()) ar(cereal::make_nvp("cursor", cursor.unpack().second));
    requested_attributes.save(ar);
    query_types.save(ar);
}

uint
QueryRequest::getAssetsLimit() const
{
    return assets_limit;
}

const SerializableQueryFilter &
QueryRequest::getQuery() const
{
    return query;
}

const SerializableAttributesMap &
QueryRequest::getRequestedAttributes() const
{
    return requested_attributes;
}

void
QueryRequest::addCondition (
    Condition condition_type,
    const string &key,
    const string &value,
    AttributeKeyType attribute_type
) {
    query.addCondition(condition_type, createAttributeString(key, attribute_type), value);
}

void
QueryRequest::addCondition (
    Condition condition_type,
    const string &key,
    const int64_t &value,
    AttributeKeyType attribute_type
) {
    query.addCondition(condition_type, createAttributeString(key, attribute_type), value);
}

void
QueryRequest::setRequestedAttr(const string &attr, AttributeKeyType attr_type)
{
    setRequestedAttr(attr, default_min_confidence, attr_type);
}

void
QueryRequest::setRequestedAttr(const string &attr, uint min_conf, AttributeKeyType attr_type)
{
    requested_attributes.setSerializableAttribute(createAttributeString(attr, attr_type), min_conf);
}

void
QueryRequest::setTenantsList(const vector<string> tenants)
{
    query_types.setSerializableTenantList(tenants);
}

void
QueryRequest::setCrossTenantAssetDB(bool cross_tenant_asset_db)
{
    query_types.setQueryCrossTenantAssetDB(cross_tenant_asset_db);
}

void
QueryRequest::setAssetsLimit(uint _assets_limit)
{
    assets_limit = _assets_limit;
}

bool
QueryRequest::checkMinConfidence(uint upper_confidence_limit)
{
    return requested_attributes.checkMinConfidence(upper_confidence_limit);
}

void
QueryRequest::activatePaging()
{
    cursor = RequestCursor(CursorState::START, "start");
}

bool
QueryRequest::isPagingActivated()
{
    return cursor.ok();
}

Maybe<CursorState>
QueryRequest::getCursorState()
{
    if (!cursor.ok()) return genError("Paging not activated");
    return cursor.unpack().first;
}

bool
QueryRequest::isPagingFinished()
{
    if (!cursor.ok()) throw IntelligenceException("Paging is not activated.");
    return cursor.unpack().first == CursorState::DONE;
}

void
QueryRequest::setCursor(CursorState state, const string &value)
{
    cursor = RequestCursor(state, value);
}

void
QueryRequest::setObjectType(const ObjectType &obj_type)
{
    object_type = obj_type;
}

QueryRequest
QueryRequest::calcQueryRequestOperator(const QueryRequest &other_query, const Operator &operator_type)
{
    QueryRequest res_req_query;
    SerializableQueryFilter res_query_filter;
    if (operator_type == Operator::AND) {
        dbgTrace(D_INTELLIGENCE) << "Calculating query request AND operator";
        res_query_filter = (this->query && other_query.getQuery());
    } else if (operator_type == Operator::OR) {
        dbgTrace(D_INTELLIGENCE) << "Calculating query request OR operator";
        res_query_filter = (this->query || other_query.getQuery());
    }
    res_req_query.query = res_query_filter;
    res_req_query.assets_limit = this->assets_limit;
    res_req_query.full_response = this->full_response;
    res_req_query.cursor = this->cursor;
    res_req_query.requested_attributes = this->requested_attributes;
    res_req_query.query_types = this->query_types;

    return res_req_query;
}

QueryRequest
QueryRequest::operator &&(const QueryRequest &other_query)
{
    return calcQueryRequestOperator(other_query, Operator::AND);
}

QueryRequest
QueryRequest::operator ||(const QueryRequest &other_query)
{
    return calcQueryRequestOperator(other_query, Operator::OR);
}
