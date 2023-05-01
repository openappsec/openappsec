#include "cache.h"

#include "cptest.h"

#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace chrono;
using namespace testing;

class Int
{
public:
    Int() {}
    Int(const int &_val) : val(_val) {}
    Int(int &&_val) : val(move(_val)) {}

    operator int() { return val; }
    Int & operator=(const int _val) { val = _val; return *this; }
    bool operator==(const int _val) const { return val == _val; }

private:
    int val = 0;
};

TEST(TempCaching, value_existing)
{
    TemporaryCache<int, Int> cache;

    EXPECT_FALSE(cache.doesKeyExists(0));

    cache.createEntry(0);
    EXPECT_TRUE(cache.doesKeyExists(0));

    cache.deleteEntry(0);
    EXPECT_FALSE(cache.doesKeyExists(0));
}

TEST(TempCaching, void_existing)
{
    TemporaryCache<int, void> cache;

    EXPECT_FALSE(cache.doesKeyExists(0));

    cache.createEntry(0);
    EXPECT_TRUE(cache.doesKeyExists(0));

    cache.deleteEntry(0);
    EXPECT_FALSE(cache.doesKeyExists(0));
}

TEST(TempCaching, value_get)
{
    TemporaryCache<int, Int> cache;
    cache.createEntry(0);

    EXPECT_EQ(cache.getEntry(0), 0);

    cache.getEntry(0) = 9;

    EXPECT_EQ(cache.getEntry(0), 9);
}

TEST(TempCaching, value_emplace)
{
    TemporaryCache<int, Int> cache;
    int val = 9;

    cache.emplaceEntry(0, val);
    EXPECT_EQ(cache.getEntry(0), 9);
    EXPECT_EQ(val, 9);


    cache.emplaceEntry(1, move(val));
    EXPECT_EQ(cache.getEntry(0), 9);
    EXPECT_EQ(cache.getEntry(1), 9);
    EXPECT_EQ(val, 9);
}

TEST(TempCaching, value_get_const)
{
    TemporaryCache<int, Int> cache;
    cache.emplaceEntry(3, 27);

    auto &const_cache = const_cast<const TemporaryCache<int, Int> &>(cache);

    EXPECT_FALSE(const_cache.getEntry(0).ok());
    EXPECT_TRUE(const_cache.getEntry(3).ok());
    EXPECT_EQ(const_cache.getEntry(3).unpack(), 27);
}

TEST(TempCaching, get_uninitialized_value)
{
    TemporaryCache<int, Int> cache;
    EXPECT_FALSE(cache.doesKeyExists(0));

    EXPECT_EQ(cache.getEntry(0), 0);

    EXPECT_TRUE(cache.doesKeyExists(0));
}

TEST(TempCaching, expiration)
{
    StrictMock<MockMainLoop> mock_ml;
    auto i_mainloop = Singleton::Consume<I_MainLoop>::from<MockProvider<I_MainLoop>>();
    StrictMock<MockTimeGet> mock_time;
    auto i_time_get = Singleton::Consume<I_TimeGet>::from<MockProvider<I_TimeGet>>();
    TemporaryCache<int, Int> cache;

    EXPECT_FALSE(cache.doesKeyExists(0));
    cache.createEntry(0);
    EXPECT_TRUE(cache.doesKeyExists(0));

    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, _, _)).WillOnce(DoAll(SaveArg<2>(&routine), Return(1)));
    cache.startExpiration(seconds(10), i_mainloop, i_time_get);
    EXPECT_FALSE(cache.doesKeyExists(0));

    EXPECT_CALL(mock_time, getMonotonicTime()).WillOnce(Return(seconds(2)));
    cache.createEntry(0);
    EXPECT_TRUE(cache.doesKeyExists(0));

    EXPECT_CALL(mock_time, getMonotonicTime()).WillOnce(Return(seconds(6)));
    cache.createEntry(1);
    EXPECT_TRUE(cache.doesKeyExists(0));
    EXPECT_TRUE(cache.doesKeyExists(1));

    EXPECT_CALL(mock_time, getMonotonicTime()).WillOnce(Return(seconds(14)));
    routine();
    EXPECT_FALSE(cache.doesKeyExists(0));
    EXPECT_TRUE(cache.doesKeyExists(1));

    EXPECT_CALL(mock_time, getMonotonicTime()).WillOnce(Return(seconds(24)));
    routine();
    EXPECT_FALSE(cache.doesKeyExists(0));
    EXPECT_FALSE(cache.doesKeyExists(1));

    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_CALL(mock_ml, stop(1));
    cache.endExpiration();
}

TEST(TempCaching, capacity)
{
    TemporaryCache<int, Int> cache;
    cache.createEntry(0);
    cache.createEntry(1);
    cache.createEntry(2);
    cache.createEntry(3);
    cache.createEntry(4);

    EXPECT_EQ(cache.size(), 5);
    EXPECT_EQ(cache.capacity(), 0);
    cache.capacity(3);
    EXPECT_EQ(cache.size(), 3);
    EXPECT_FALSE(cache.doesKeyExists(0));
    EXPECT_FALSE(cache.doesKeyExists(1));
    EXPECT_TRUE(cache.doesKeyExists(2));
    EXPECT_TRUE(cache.doesKeyExists(3));
    EXPECT_TRUE(cache.doesKeyExists(4));

    cache.createEntry(5);
    EXPECT_EQ(cache.size(), 3);
    EXPECT_FALSE(cache.doesKeyExists(2));
    EXPECT_TRUE(cache.doesKeyExists(3));
    EXPECT_TRUE(cache.doesKeyExists(4));
    EXPECT_TRUE(cache.doesKeyExists(5));

    cache.capacity(0);
    cache.createEntry(6);
    EXPECT_EQ(cache.size(), 4);
    EXPECT_TRUE(cache.doesKeyExists(3));
    EXPECT_TRUE(cache.doesKeyExists(4));
    EXPECT_TRUE(cache.doesKeyExists(5));
    EXPECT_TRUE(cache.doesKeyExists(6));

    cache.deleteEntry(5);
    cache.capacity(2);
    EXPECT_EQ(cache.size(), 2);
    EXPECT_TRUE(cache.doesKeyExists(4));
    EXPECT_TRUE(cache.doesKeyExists(6));
}
