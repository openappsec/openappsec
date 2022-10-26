#include <cmock/cmock.h>

#include "math.h"

using namespace ::testing;

class MathMocker : public CMockMocker<MathMocker>
{
public:
    MOCK_METHOD2(add, int(int, int));
    MOCK_METHOD2(substract, int(int, int));
    MOCK_METHOD1(negate, int(int));
};

CMOCK_MOCK_FUNCTION2(MathMocker, add, int(int, int));
CMOCK_MOCK_FUNCTION2(MathMocker, substract, int(int, int));
CMOCK_MOCK_FUNCTION1(MathMocker, negate, int(int));

/**
 * Functions add and substract are mocked as long as MathMocker instance exists.
 * Once a mock function is destroyed, a call directs to a real function.
 */
TEST(FunctionClassMockersOldStyleTest, MocksFunctionAsLongAsMockerInstanceExists) {

	{
		MathMocker mock;

		EXPECT_CALL(mock, add(1, 1)).WillOnce(Return(11));
		ASSERT_EQ(11, add(1, 1));

		EXPECT_CALL(mock, substract(1, 2)).WillOnce(Return(12));
		ASSERT_EQ(12, substract(1, 2));
	}

	ASSERT_EQ(2, add(1, 1));
	ASSERT_EQ(-1, substract(1, 2));
}

TEST(FunctionClassMockersOldStyleTest, ThrowsExceptionIfRealFunctionNotFound) {

	{
		MathMocker mock;

		EXPECT_CALL(mock, negate(3)).WillOnce(Return(-3));
		ASSERT_EQ(-3, negate(3));
	}

	EXPECT_THROW(negate(3), std::logic_error);
}
