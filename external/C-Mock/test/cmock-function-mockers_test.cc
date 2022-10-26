#include <cmock/cmock.h>

#include "math.h"

using namespace ::testing;

DECLARE_FUNCTION_MOCK2(AddFunctionMock, add, int(int, int));
DECLARE_FUNCTION_MOCK1(NegateFunctionMock, negate, int(int));

IMPLEMENT_FUNCTION_MOCK2(AddFunctionMock, add, int(int, int));
IMPLEMENT_FUNCTION_MOCK1(NegateFunctionMock, negate, int(int));

/**
 * Function add is mocked as long as AddFunctionMock instance exists.
 * Once mock function is destroyed, a call directs to a real function.
 */
TEST(FunctionMockersTest, MocksFunctionAsLongAsMockInstanceExists) {

	{
		AddFunctionMock mock;

		EXPECT_FUNCTION_CALL(mock, (1, 2)).WillOnce(Return(12));
		ASSERT_EQ(12, add(1, 2));
	}

	ASSERT_EQ(3, add(1, 2));
}

/**
 * real static mock class field holds pointer to a real function.
 */
TEST(FunctionMockersTest, FunctionMockExportsRealFunctionPointer) {
	EXPECT_EQ(3, AddFunctionMock::real(1, 2));
}

/**
 * Function negate doesn't exist, but can be mocked.
 */
TEST(FunctionMockersTest, ThrowsExceptionIfRealFunctionNotFound)
{
	{
		NegateFunctionMock mock;

		EXPECT_FUNCTION_CALL(mock, (9)).WillOnce(Return(3));

		ASSERT_EQ(3, negate(9));
	}

	EXPECT_THROW(negate(9), std::logic_error);
}
