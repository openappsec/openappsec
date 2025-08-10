// Copyright (C) 2023 Check Point Software Technologies Ltd. All rights reserved.

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

#include "intelligence_request.h"
#include "intelligence_is_v2/query_request_v2.h"

#include "cptest.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_INTELLIGENCE);

TEST(IntelligenceQueryTestV2, genJsonPrettySingleRequest) {
    QueryRequest request(Condition::EQUALS, "phase", "testing", true);
    vector<QueryRequest> requests = {request};
    Intelligence::IntelligenceRequest query(requests, true, false, false, MessageMetadata("", 0));

    std::string expected = "{\n"
        "    \"queryTypes\": {\n"
        "        \"proxyToCloud\": false\n"
        "    },\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"equals\",\n"
        "        \"key\": \"mainAttributes.phase\",\n"
        "        \"value\": \"testing\"\n"
        "    }\n"
        "}";

    EXPECT_EQ(*query.genJson(), expected);
}

TEST(IntelligenceQueryTestV2, genJsonPrettySingleRequestProxied) {
    QueryRequest request(Condition::EQUALS, "phase", "testing", true);
    vector<QueryRequest> requests = {request};
    Intelligence::IntelligenceRequest query(requests, true, false, true, MessageMetadata("", 0));

    std::string expected = "{\n"
        "    \"queryTypes\": {\n"
        "        \"proxyToCloud\": true\n"
        "    },\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"equals\",\n"
        "        \"key\": \"mainAttributes.phase\",\n"
        "        \"value\": \"testing\"\n"
        "    }\n"
        "}";

    EXPECT_EQ(*query.genJson(), expected);
}

TEST(IntelligenceQueryTestV2, genJsonPrettySingleRequestExternalError) {
    QueryRequest request(Condition::EQUALS, "phase", "testing", true, AttributeKeyType::MAIN, true);
    vector<QueryRequest> requests = {request};
    Intelligence::IntelligenceRequest query(requests, true, false, true, MessageMetadata("", 0));

    std::string expected = "{\n"
        "    \"queryTypes\": {\n"
        "        \"proxyToCloud\": true\n"
        "    },\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"externalSourcesErrorStatus\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"equals\",\n"
        "        \"key\": \"mainAttributes.phase\",\n"
        "        \"value\": \"testing\"\n"
        "    }\n"
        "}";

    EXPECT_EQ(*query.genJson(), expected);
}

TEST(IntelligenceQueryTestV2, genJsonUnprettySingleRequest) {
    QueryRequest request(Condition::EQUALS, "phase", "testing", true);
    vector<QueryRequest> requests = {request};
    Intelligence::IntelligenceRequest query(requests, false, false, false, MessageMetadata("", 0));

    std::string expected = "{"
        "\"queryTypes\":{"
        "\"proxyToCloud\":false"
        "},"
        "\"limit\":20,"
        "\"fullResponse\":true,"
        "\"query\":{"
        "\"operator\":\"equals\","
        "\"key\":\"mainAttributes.phase\","
        "\"value\":\"testing\""
        "}}";

    EXPECT_EQ(*query.genJson(), expected);
}

TEST(IntelligenceQueryTestV2, genJsonUnprettySingleRequestSpaces) {
    QueryRequest request(Condition::EQUALS, "ph ase", "te sti\" n g\\", true);
    vector<QueryRequest> requests = {request};
    Intelligence::IntelligenceRequest query(requests, false, false, false, MessageMetadata("", 0));
    std::string expected = "{"
        "\"queryTypes\":{"
        "\"proxyToCloud\":false"
        "},"
        "\"limit\":20,"
        "\"fullResponse\":true,"
        "\"query\":{"
        "\"operator\":\"equals\","
        "\"key\":\"mainAttributes.ph ase\","
        "\"value\":\"te sti\\\" n g\\\\\""
        "}}";

    EXPECT_EQ(*query.genJson(), expected);
}

TEST(IntelligenceQueryTestV2, genJsonPrettyBulkRequests) {
    QueryRequest request1(Condition::EQUALS, "phase", "testing", true);
    QueryRequest request2(Condition::EQUALS, "height", "testing", 25);
    std::vector<QueryRequest> requests = {request1, request2};
    Intelligence::IntelligenceRequest query(requests, true, true, false, MessageMetadata("", 0));

    std::string expected = "{\n"
        "    \"queriesTypes\": {\n"
        "        \"proxyToCloud\": false\n"
        "    },\n"
        "    \"queries\": [\n"
        "        {\n"
        "            \"query\": {\n"
        "                \"limit\": 20,\n"
        "                \"fullResponse\": true,\n"
        "                \"query\": {\n"
        "                    \"operator\": \"equals\",\n"
        "                    \"key\": \"mainAttributes.phase\",\n"
        "                    \"value\": \"testing\"\n"
        "                }\n"
        "            },\n"
        "            \"index\": 0\n"
        "        },\n"
        "        {\n"
        "            \"query\": {\n"
        "                \"limit\": 20,\n"
        "                \"fullResponse\": true,\n"
        "                \"query\": {\n"
        "                    \"operator\": \"equals\",\n"
        "                    \"key\": \"mainAttributes.height\",\n"
        "                    \"value\": \"testing\"\n"
        "                }\n"
        "            },\n"
        "            \"index\": 1\n"
        "        }\n"
        "    ]\n"
        "}";

    EXPECT_EQ(*query.genJson(), expected);
}

TEST(IntelligenceQueryTestV2, genJsonPrettyBulkRequestsProxied) {
    QueryRequest request1(Condition::EQUALS, "phase", "testing", true);
    QueryRequest request2(Condition::EQUALS, "height", "testing", 25);
    std::vector<QueryRequest> requests = {request1, request2};
    Intelligence::IntelligenceRequest query(requests, true, true, true, MessageMetadata("", 0));

    std::string expected = "{\n"
        "    \"queriesTypes\": {\n"
        "        \"proxyToCloud\": true\n"
        "    },\n"
        "    \"queries\": [\n"
        "        {\n"
        "            \"query\": {\n"
        "                \"limit\": 20,\n"
        "                \"fullResponse\": true,\n"
        "                \"query\": {\n"
        "                    \"operator\": \"equals\",\n"
        "                    \"key\": \"mainAttributes.phase\",\n"
        "                    \"value\": \"testing\"\n"
        "                }\n"
        "            },\n"
        "            \"index\": 0\n"
        "        },\n"
        "        {\n"
        "            \"query\": {\n"
        "                \"limit\": 20,\n"
        "                \"fullResponse\": true,\n"
        "                \"query\": {\n"
        "                    \"operator\": \"equals\",\n"
        "                    \"key\": \"mainAttributes.height\",\n"
        "                    \"value\": \"testing\"\n"
        "                }\n"
        "            },\n"
        "            \"index\": 1\n"
        "        }\n"
        "    ]\n"
        "}";

    EXPECT_EQ(*query.genJson(), expected);
}

TEST(IntelligenceQueryTestV2, genJsonUnprettyBulkRequest) {
    QueryRequest request1(Condition::EQUALS, "phase", "testing", true);
    QueryRequest request2(Condition::EQUALS, "height", "testing", 25);
    std::vector<QueryRequest> requests = {request1, request2};
    Intelligence::IntelligenceRequest query(requests, false, true, false, MessageMetadata("", 0));

    std::string expected = "{"
            "\"queriesTypes\":{"
            "\"proxyToCloud\":false"
            "},"
            "\"queries\":[{"
            "\"query\":{"
            "\"limit\":20,"
            "\"fullResponse\":true,"
            "\"query\":{"
            "\"operator\":\"equals\","
            "\"key\":\"mainAttributes.phase\","
            "\"value\":\"testing\""
            "}},"
            "\"index\":0"
            "},{"
            "\"query\":{"
            "\"limit\":20,"
            "\"fullResponse\":true,"
            "\"query\":{"
            "\"operator\":\"equals\","
            "\"key\":\"mainAttributes.height\","
            "\"value\":\"testing\""
            "}},"
            "\"index\":1"
            "}]}";

    EXPECT_EQ(*query.genJson(), expected);
}
