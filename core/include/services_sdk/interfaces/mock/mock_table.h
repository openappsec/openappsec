#ifndef __MOCK_TABLE_H__
#define __MOCK_TABLE_H__

#include <gmock/gmock.h>

#include "i_table.h"
#include "singleton.h"
#include "cptest.h"

class MockTable : public Singleton::Provide<I_Table>::From<MockProvider<I_Table>>
{
public:
    MOCK_METHOD1(setExpiration, void(std::chrono::milliseconds expire));
    MOCK_CONST_METHOD0(doesKeyExists, bool());
    MOCK_CONST_METHOD0(keyToString, std::string());
    MOCK_CONST_METHOD0(begin, TableIter());
    MOCK_CONST_METHOD0(end, TableIter());

    bool
    createState(const std::type_index &index, std::unique_ptr<TableOpaqueBase> &&ptr)
    {
        return createStateRValueRemoved(index, ptr);
    }

    MOCK_CONST_METHOD1(hasState, bool(const std::type_index &index));
    MOCK_METHOD2(createStateRValueRemoved, bool(const std::type_index &index, std::unique_ptr<TableOpaqueBase> &ptr));
    MOCK_METHOD1(deleteState, bool(const std::type_index &index));
    MOCK_METHOD1(getState, TableOpaqueBase *(const std::type_index &index));
};

#endif // __MOCK_TABLE_H__
