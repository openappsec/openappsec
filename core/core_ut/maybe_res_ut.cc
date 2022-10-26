#include "cptest.h"
#include "maybe_res.h"

#include <vector>
#include <tuple>
#include <set>

using namespace std;
using namespace testing;

static Maybe<int>
returnIfEven(int i)
{
    if (i%2 == 1) return genError("Odd number");
    return i;
}

TEST(Usage, typical_function)
{
    auto even = returnIfEven(4);
    ASSERT_TRUE(even.ok());
    EXPECT_EQ(4, *even);
    EXPECT_THAT(even, IsValue(4));

    auto odd = returnIfEven(5);
    ASSERT_FALSE(odd.ok());
    EXPECT_EQ("Odd number", odd.getErr());
    EXPECT_THAT(odd, IsError("Odd number"));
}

TEST(genError, explicit_build)
{
    Error<string> err = genError<string>("error");
}

TEST(genError, implicit_build)
{
    Error<string> err = genError(string("error"));
}

TEST(genError, paramaters_build)
{
    string str = "error";
    Error<vector<char>> err = genError<vector<char>>(str.begin(), str.end());
}

TEST(genError, void_build)
{
    Error<void> err1 = genError<void>();
    Error<void> err2 = genError<void>(5, 6, 7);
    EXPECT_TRUE(err1 == err2);
}

TEST(Maybe, basic_error)
{
    Maybe<int> res = genError<string>("error");
    ASSERT_FALSE(res.ok());
    EXPECT_EQ(string("error"), res.getErr());
    EXPECT_THAT(res, IsError("error"));
}

TEST(Maybe, basic_value)
{
    Maybe<int> res = 5;
    ASSERT_TRUE(res.ok());
    EXPECT_EQ(5, res.unpack());
    EXPECT_EQ(5, static_cast<int>(*res));
    EXPECT_EQ(5, *res);
    EXPECT_THAT(res, IsValue(5));
}

TEST(Maybe, error_cast)
{
    Maybe<int> res = genError<const char *>("error");
    EXPECT_THAT(res, IsError("error"));
}

TEST(Maybe, error_cast_impilicit)
{
    Maybe<int> res = genError("error");
    EXPECT_THAT(res, IsError("error"));
}

TEST(Maybe, unpack_execption)
{
    Maybe<int> res = 5;
    EXPECT_EQ(5, res.unpack<string>());

    Maybe<int> err = genError("error");

    EXPECT_THROW(err.unpack<string>(), string);
    try {
        err.unpack<string>();
    } catch (string str) {
        EXPECT_EQ("error", str);
    }

    EXPECT_THROW(err.unpack<string>("really ", "bad "), string);
    try {
        err.unpack<string>("really ", "bad ");
    } catch (string str) {
        EXPECT_EQ("really bad error", str);
    }
}

TEST(Maybe, verify)
{
    Maybe<int> res = 5;
    res.verify<string>();
    res.verify<string>("really ", "bad ");

    Maybe<int> err = genError("error");

    EXPECT_THROW(err.verify<string>(), string);
    try {
        err.verify<string>();
    } catch (string str) {
        EXPECT_EQ("error", str);
    }

    EXPECT_THROW(err.verify<string>("really ", "bad "), string);
    try {
        err.verify<string>("really ", "bad ");
    } catch (string str) {
        EXPECT_EQ("really bad error", str);
    }
}

TEST(Maybe, equalValue)
{
    Maybe<int> a=1, b=1, c=2;
    EXPECT_TRUE (a==b);
    EXPECT_FALSE(a==c);
    EXPECT_TRUE (a!=c);
    EXPECT_FALSE(a!=b);
}

TEST(Maybe, equalError)
{
    Maybe<char, int> a=genError(1), b=genError(1), c=genError(2);
    EXPECT_TRUE (a==b);
    EXPECT_FALSE(a==c);
    EXPECT_TRUE (a!=c);
    EXPECT_FALSE(a!=b);

    Maybe<int> d=genError("error1");
    Maybe<int> e=genError("error2");

    EXPECT_FALSE(d==e);
}


class MaybeAssignments : public Test
{
public:
    // A class to use as a value.
    // Maybe runs constructors and destructors manually, so we verify that they're
    //   called properly.
    class MyValue
    {
    public:
        MyValue(int _x) : x(_x) { addObj(this); }
        MyValue(const MyValue &other) : x(other.x) {  addObj(this); }
        ~MyValue() { delObj(this); }
        bool operator==(const MyValue &other) const { return x==other.x; }
        bool operator!=(const MyValue &other) const { return x!=other.x; }

        int x;

        // Tracking all existing objects
        static set<const MyValue *> objects;

        static void
        addObj(const MyValue *obj)
        {
            EXPECT_EQ(objects.end(), objects.find(obj));
            objects.insert(obj);
        }

        static void
        delObj(const MyValue *obj)
        {
            EXPECT_NE(objects.end(), objects.find(obj));
            objects.erase(obj);
        }
    };

    MaybeAssignments()
    {
        MyValue::objects.clear();
    }

    ~MaybeAssignments()
    {
        EXPECT_THAT(MyValue::objects, IsEmpty());
    }
};

set<const MaybeAssignments::MyValue *> MaybeAssignments::MyValue::objects;

// Testing assignment of a new value. Combinations:
//   Old is value / error
//   New is value / error
//   New is L-value / R-value

TEST_F(MaybeAssignments, ValValRval)
{
    Maybe<MyValue, MyValue> m(MyValue(1));

    // Change the value
    EXPECT_EQ(1, m->x);
    m = 2;
    EXPECT_EQ(2, m->x);
}

TEST_F(MaybeAssignments, ValValLval)
{
    Maybe<MyValue, MyValue> m(MyValue(1));

    // Change the value
    EXPECT_EQ(1, m->x);
    MyValue v = 2;
    m = v;
    EXPECT_EQ(2, m->x);
}

TEST_F(MaybeAssignments, ErrValRval)
{
    Maybe<MyValue, MyValue> m(genError(404));

    // Convert an error to a value
    EXPECT_EQ(MyValue(404), m.getErr());
    m = 3;
    EXPECT_EQ(3, m->x);
}

TEST_F(MaybeAssignments, ErrValLval)
{
    Maybe<MyValue, MyValue> m(genError(404));

    // Convert an error to a value
    EXPECT_EQ(MyValue(404), m.getErr());
    MyValue v = 3;
    m = v;
    EXPECT_EQ(3, m->x);
}

TEST_F(MaybeAssignments, ValErrRval)
{
    Maybe<MyValue, MyValue> m(MyValue(1));

    // Convert a value to an error
    EXPECT_EQ(1, m->x);
    m = genError(500);
    EXPECT_EQ(MyValue(500), m.getErr());
}

TEST_F(MaybeAssignments, ValErrLval)
{
    Maybe<MyValue, MyValue> m(MyValue(1));

    // Convert a value to an error
    EXPECT_EQ(1, m->x);
    Error<MyValue> e(500);
    m = e;
    EXPECT_EQ(MyValue(500), m.getErr());
}

TEST_F(MaybeAssignments, ErrErrRval)
{
    Maybe<uint> m(genError("404"));

    // Change the error
    EXPECT_EQ("404", m.getErr());
    Error<string> e("500");
    m = move(e);
    EXPECT_EQ("500", m.getErr());
}

TEST_F(MaybeAssignments, ErrErrLval)
{
    Maybe<MyValue, MyValue> m(genError(404));

    // Change the error
    EXPECT_EQ(MyValue(404), m.getErr());
    Error<MyValue> e(500);
    m = e;
    EXPECT_EQ(MyValue(500), m.getErr());
}


class ErrorTranslator
{
public:
    template <typename Err>
    ErrorTranslator(const map<Err, string> &m, Err err) : str(m.at(err)) {}

    operator string() { return str; }

private:
    string str;
};

TEST(Maybe, diff_aggr)
{
    Maybe<int, int> err = genError(8);
    map<int, string> trans = { { 8, "my error" } };
    try {
        err.verify<string, ErrorTranslator>(trans);
    } catch (string str) {
        EXPECT_EQ("my error", str);
    }
}

TEST(Maybe, illegal_access)
{
    cptestPrepareToDie();

    Maybe<int> err = genError("error");
    EXPECT_DEATH(*err, "Maybe value is not set");
    EXPECT_DEATH(err.unpack(), "Maybe value is not set");

    Maybe<int> res = 5;
    EXPECT_DEATH(res.getErr(), "Maybe value is set");
}

TEST(Maybe, passing_error)
{
    Maybe<int>    err1 = genError("error");
    Maybe<string> err2 = err1.passErr();

    EXPECT_THAT(err2, IsError("error"));
}

TEST(Maybe, maybe_void)
{
    cptestPrepareToDie();

    Maybe<void> res;
    EXPECT_TRUE(res.ok());

    EXPECT_DEATH(res.getErr(), "Maybe value is set");
}


TEST(Maybe, maybe_void_error)
{
    Maybe<void> err = genError("error");

    EXPECT_THAT(err, IsError("error"));
}

TEST(Maybe, maybe_void_error_passing)
{
    Maybe<int>  err1 = genError("error");
    Maybe<void> err2 = err1.passErr();

    EXPECT_FALSE(err2.ok());
    EXPECT_EQ("error", err2.getErr());
}

TEST(Maybe, printing)
{
    ostringstream os;
    Maybe<int> val1 = 5;
    os << val1;
    EXPECT_EQ("Value(5)", os.str());

    os.str("");
    Maybe<void> val2;
    os << val2;
    EXPECT_EQ("Value()", os.str());

    os.str("");
    Maybe<int> err1 = genError("error");
    os << err1;
    EXPECT_EQ("Error(error)", os.str());

    os.str("");
    Maybe<void> err2 = genError("error");;
    os << err2;
    EXPECT_EQ("Error(error)", os.str());

}


TEST(Maybe, cast_value)
{
    Maybe<int> val1 = 5;
    Maybe<double> val2(val1);
    EXPECT_THAT(val2, IsValue(5.0));
}

TEST(Maybe, cast_err)
{
    Maybe<string, int> err1 = genError(3);
    Maybe<string, double> err2 = move(err1);
    EXPECT_THAT(err2, IsError(3.0));
}

TEST(Maybe, cast_err_void)
{
    Maybe<int, int> err1 = genError(3);
    Maybe<double, void> err2 = err1;
    EXPECT_FALSE(err2.ok());
}
