#include <cmock/cmock.h>

#include "math.h"

using namespace ::testing;

class MathMocker : public CMockMocker<MathMocker>
{
public:
    CMOCK_MOCK_METHOD(int, add, (int, int));
    CMOCK_MOCK_METHOD(int, substract, (int, int));
    CMOCK_MOCK_METHOD(int, negate, (int));
};

CMOCK_MOCK_FUNCTION(MathMocker, int, add, (int, int));
CMOCK_MOCK_FUNCTION(MathMocker, int, substract, (int, int));
CMOCK_MOCK_FUNCTION(MathMocker, int, negate, (int));

/**
 * Functions add and substract are mocked as long as MathMocker instance exists.
 * Once a mock function is destroyed, a call directs to a real function.
 */
TEST(FunctionClassMockersTest, MocksFunctionAsLongAsMockerInstanceExists) {

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

TEST(FunctionClassMockersTest, ThrowsExceptionIfRealFunctionNotFound) {

	{
		MathMocker mock;

		EXPECT_CALL(mock, negate(3)).WillOnce(Return(-3));
		ASSERT_EQ(-3, negate(3));
	}

	EXPECT_THROW(negate(3), std::logic_error);
}

TEST(FunctionClassMockersTest, ProvidesMeansToCallRealFunction) {

	{
		MathMocker mock;

		ASSERT_EQ(2, CMOCK_REAL_FUNCTION(MathMocker, add)(1, 1));
	}

	ASSERT_EQ(2, CMOCK_REAL_FUNCTION(MathMocker, add)(1, 1));
}
