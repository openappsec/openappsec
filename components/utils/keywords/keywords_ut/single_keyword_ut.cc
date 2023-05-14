#include "../sentinel_runtime_state.h"
#include "../single_keyword.h"
#include "cptest.h"
#include <list>

using namespace std;
using namespace testing;

#define FIRST_VARIABLE_ID 1
#define FIRST_VARIABLE_VAL 2u
#define SECOND_VARIABLE_ID 3
#define SECOND_VARIABLE_VAL 4u
#define THIRD_VARIABLE_ID 5
#define THIRD_VARIABLE_VAL 6u

#define FIRST_OFFSET 4u
#define SECOND_OFFSET 5u
#define THIRD_OFFSET 6u

const static unsigned int zero = 0;

class I_KeywordRuntimeStateTest : public Test
{
public:
    //  Constructs SentinelKeyword as head because it is the only I_KeywordRuntimeState implementation
    //  that does not hold I_KeywordRuntimeState *prev
    I_KeywordRuntimeStateTest() : list_head(&sentinel) {}

    uint
    getOffset(const string &id)
    {
        return list_head->getOffset(id);
    }

    uint
    getVariable(uint requested_var_id)
    {
        return list_head->getVariable(requested_var_id);
    }

    void
    addOffsetState(const string &_ctx, uint _offset)
    {
        offset_list.push_front(make_unique<OffsetRuntimeState>(list_head, _ctx, _offset));
        list_head = offset_list.front().get();
    }

    void
    addVariableState(uint _var_id, uint _val)
    {
        variable_list.push_front(make_unique<VariableRuntimeState>(list_head, _var_id, _val));
        list_head = variable_list.front().get();
    }

private:
    list<unique_ptr<VariableRuntimeState>> variable_list;
    list<unique_ptr<OffsetRuntimeState>> offset_list;
    SentinelRuntimeState sentinel;
    I_KeywordRuntimeState *list_head;
};

TEST_F(I_KeywordRuntimeStateTest, one_element_list_positive_test) {
    EXPECT_EQ(getOffset("HTTP_METHOD"), zero);
    EXPECT_EQ(getOffset("HTTP_REQ_COOKIE"), zero);
    EXPECT_EQ(getOffset("HTTP_REQUEST_HEADERS"), zero);
}

TEST_F(I_KeywordRuntimeStateTest, one_variable_state_list_positive_test) {
    addVariableState(FIRST_VARIABLE_ID, FIRST_VARIABLE_VAL);
    EXPECT_EQ(getOffset("HTTP_COMPLETE_URL_ENCODED"), zero);
    EXPECT_EQ(getOffset("HTTP_METHOD"), zero);
    EXPECT_EQ(getVariable(FIRST_VARIABLE_ID), FIRST_VARIABLE_VAL);
}

TEST_F(I_KeywordRuntimeStateTest, one_offset_state_list_positive_test) {
    EXPECT_EQ(getOffset("HTTP_REQUEST_HEADERS"), zero);
    addOffsetState("HTTP_REQUEST_HEADERS", FIRST_OFFSET);
    EXPECT_EQ(getOffset("HTTP_REQUEST_HEADERS"), FIRST_OFFSET);
}

TEST_F(I_KeywordRuntimeStateTest, one_element_list_negative_test) {
    cptestPrepareToDie();
    EXPECT_DEATH(getVariable(FIRST_OFFSET), "");
    EXPECT_DEATH(getVariable(SECOND_OFFSET), "");
    EXPECT_DEATH(getVariable(THIRD_OFFSET), "");
}

TEST_F(I_KeywordRuntimeStateTest, variable_runtime_state_list_positive_test) {
    //  Notice that variables ids and values are different
    addVariableState(FIRST_VARIABLE_ID, FIRST_VARIABLE_VAL);
    addVariableState(SECOND_VARIABLE_ID, SECOND_VARIABLE_VAL);
    addVariableState(THIRD_VARIABLE_ID, THIRD_VARIABLE_VAL);

    EXPECT_EQ(getOffset("HTTP_METHOD"), zero);
    EXPECT_EQ(getOffset("HTTP_COMPLETE_URL_ENCODED"), zero);
    EXPECT_EQ(getOffset("HTTP_REQ_COOKIE"), zero);
    EXPECT_EQ(getOffset("HTTP_REQUEST_HEADERS"), zero);
    EXPECT_EQ(getOffset("HTTP_REQUEST_BODY"), zero);

    EXPECT_EQ(getVariable(FIRST_VARIABLE_ID), FIRST_VARIABLE_VAL);
    EXPECT_EQ(getVariable(SECOND_VARIABLE_ID), SECOND_VARIABLE_VAL);
    EXPECT_EQ(getVariable(THIRD_VARIABLE_ID), THIRD_VARIABLE_VAL);
}

TEST_F(I_KeywordRuntimeStateTest, OffsetRuntimeState_list_negative_test) {
    addOffsetState("HTTP_COMPLETE_URL_ENCODED", FIRST_OFFSET);
    addOffsetState("HTTP_REQ_COOKIE", SECOND_OFFSET);
    addOffsetState("HTTP_METHOD", THIRD_OFFSET);

    cptestPrepareToDie();
    EXPECT_DEATH(getVariable(FIRST_OFFSET), "");
    EXPECT_DEATH(getVariable(SECOND_OFFSET), "");
    EXPECT_DEATH(getVariable(THIRD_OFFSET), "");
}

TEST_F(I_KeywordRuntimeStateTest, offset_runtime_state_list_positive_test) {
    EXPECT_EQ(getOffset("HTTP_REQUEST_HEADERS"), zero);
    EXPECT_EQ(getOffset("HTTP_REQ_COOKIE"), zero);

    addOffsetState("HTTP_REQUEST_HEADERS", FIRST_OFFSET);
    addOffsetState("HTTP_REQ_COOKIE", SECOND_OFFSET);

    EXPECT_EQ(getOffset("HTTP_REQUEST_HEADERS"), FIRST_OFFSET);
    EXPECT_EQ(getOffset("HTTP_REQ_COOKIE"), SECOND_OFFSET);
}

TEST_F(I_KeywordRuntimeStateTest, mixed_types_list_positive_test) {
    EXPECT_EQ(getOffset("HTTP_COMPLETE_URL_ENCODED"), zero);
    EXPECT_EQ(getOffset("HTTP_METHOD"), zero);

    addOffsetState("HTTP_COMPLETE_URL_ENCODED", FIRST_OFFSET);
    addVariableState(SECOND_VARIABLE_ID, SECOND_VARIABLE_VAL);
    addOffsetState("HTTP_METHOD", THIRD_OFFSET);

    EXPECT_EQ(getOffset("HTTP_COMPLETE_URL_ENCODED"), FIRST_OFFSET);
    EXPECT_EQ(getOffset("HTTP_METHOD"), THIRD_OFFSET);

    EXPECT_EQ(getVariable(SECOND_VARIABLE_ID), SECOND_VARIABLE_VAL);
}

TEST_F(I_KeywordRuntimeStateTest, mixed_types_list_negative_test) {
    addOffsetState("HTTP_COMPLETE_URL_ENCODED", FIRST_OFFSET);
    addVariableState(SECOND_VARIABLE_ID, SECOND_VARIABLE_VAL);
    addOffsetState("HTTP_METHOD", THIRD_OFFSET);

    cptestPrepareToDie();
    EXPECT_DEATH(getVariable(FIRST_OFFSET), "");
    EXPECT_DEATH(getVariable(THIRD_OFFSET), "");
}

TEST_F(I_KeywordRuntimeStateTest, mixed_types_list_offset_shadowing_test) {
    addOffsetState("HTTP_COMPLETE_URL_ENCODED", FIRST_OFFSET);

    EXPECT_EQ(getOffset("HTTP_COMPLETE_URL_ENCODED"), FIRST_OFFSET);

    addVariableState(SECOND_VARIABLE_ID, SECOND_VARIABLE_VAL);
    addOffsetState("HTTP_COMPLETE_URL_ENCODED", THIRD_OFFSET);

    EXPECT_EQ(getOffset("HTTP_COMPLETE_URL_ENCODED"), THIRD_OFFSET);
}

TEST_F(I_KeywordRuntimeStateTest, mixed_types_list_variable_shadowing_test) {
    addVariableState(FIRST_VARIABLE_ID, FIRST_VARIABLE_VAL);

    EXPECT_EQ(getVariable(FIRST_VARIABLE_ID), FIRST_VARIABLE_VAL);

    addOffsetState("HTTP_COMPLETE_URL_ENCODED", SECOND_OFFSET);
    addVariableState(FIRST_VARIABLE_ID, THIRD_VARIABLE_VAL);

    EXPECT_EQ(getVariable(FIRST_VARIABLE_ID), THIRD_VARIABLE_VAL);
}
