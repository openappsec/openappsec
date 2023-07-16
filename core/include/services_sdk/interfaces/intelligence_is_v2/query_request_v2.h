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

#ifndef __QUERY_REQUEST_V2_H__
#define __QUERY_REQUEST_V2_H__

#include "rest.h"
#include "common.h"
#include "intelligence_is_v2/intelligence_types_v2.h"
#include "intelligence_is_v2/query_filter_v2.h"
#include "intelligence_is_v2/requested_attributes_v2.h"
#include "intelligence_is_v2/query_types_v2.h"
#include "maybe_res.h"

class QueryRequest
{
public:
    using RequestCursor = std::pair<CursorState, std::string>;

    QueryRequest() {}

    QueryRequest(
        Condition condition_type,
        const std::string &key,
        const std::string &value,
        bool full_response,
        AttributeKeyType type = AttributeKeyType::MAIN
    );

    QueryRequest(
        Condition condition_type,
        const std::string &key,
        const int64_t &value,
        bool full_response,
        AttributeKeyType type = AttributeKeyType::MAIN
    );

    void saveToJson(cereal::JSONOutputArchive &ar) const;
    void save(cereal::JSONOutputArchive &ar) const;

    uint getAssetsLimit() const;
    const SerializableQueryFilter & getQuery() const;
    const SerializableAttributesMap & getRequestedAttributes() const;

    void addCondition(
        Condition condition_type,
        const std::string &key,
        const std::string &value,
        AttributeKeyType attribute_type = AttributeKeyType::MAIN
    );

    void addCondition(
        Condition condition_type,
        const std::string &key,
        const int64_t &value,
        AttributeKeyType attribute_type = AttributeKeyType::MAIN
    );

    void setRequestedAttr(
        const std::string &attr,
        AttributeKeyType attribute_type = AttributeKeyType::REGULAR
    );

    void setRequestedAttr(
        const std::string &attr,
        uint min_conf,
        AttributeKeyType = AttributeKeyType::REGULAR
    );

    void setTenantsList(const std::vector<std::string> tenants);
    void setCrossTenantAssetDB(bool cross_tenant_asset_db);
    void setObjectType(const ObjectType &obj_type);

    void setAssetsLimit(uint _assets_limit);
    bool checkMinConfidence(uint upper_confidence_limit);

    void activatePaging();
    bool isPagingActivated();
    Maybe<CursorState> getCursorState();
    bool isPagingFinished();
    void setCursor(CursorState state, const std::string &value);
    bool empty() const { return query.empty(); }

    QueryRequest operator &&(const QueryRequest &other_query);
    QueryRequest operator ||(const QueryRequest &other_query);

    static const uint default_min_confidence;
    static const uint default_assets_limit;

private:
    uint assets_limit = default_assets_limit;
    bool full_response = false;
    Maybe<ObjectType> object_type = genError("uninitialized");
    Maybe<RequestCursor> cursor = genError("Cursor not initialized");
    SerializableQueryFilter query;
    SerializableAttributesMap requested_attributes;
    SerializableQueryTypes query_types;
    QueryRequest calcQueryRequestOperator(const QueryRequest &other_query, const Operator &operator_type);
    Maybe<std::string> convertObjectTypeToString() const;
};

class BulkQueryRequest
{
public:
    BulkQueryRequest() {}

    BulkQueryRequest(QueryRequest &request, int index);
    
    void saveToJson(cereal::JSONOutputArchive &ar) const;
    void save(cereal::JSONOutputArchive &ar) const;

    QueryRequest getQueryRequest() const;

private:
    QueryRequest request;
    int index;
};

#endif // __QUERY_REQUEST_V2_H__
