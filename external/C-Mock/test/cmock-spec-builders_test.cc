#include <cmock/cmock.h>

#include "math.h"

DECLARE_FUNCTION_MOCK2(AddFunctionMock, add, int(int, int));

IMPLEMENT_FUNCTION_MOCK2(AddFunctionMock, add, int(int, int));

TEST(SpecBuildersTest, ExpectFunctionCallCompiles) {
  AddFunctionMock mock;
  EXPECT_FUNCTION_CALL(mock, (1, 2)).Times(0);
}

TEST(SpecBuildersTest, OnFunctionCallCompiles) {
  AddFunctionMock mock;
  ON_FUNCTION_CALL(mock, (1, 2));
}
