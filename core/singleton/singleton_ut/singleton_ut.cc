#include "singleton.h"
#include "cptest.h"
#include "config.h"
#include "config_component.h"

using namespace std;
using namespace testing;

class Example : public Singleton::Provide<Example>::Self
{
};

TEST(Singleton, NoObject)
{
    ::Environment env;
    ConfigComponent conf;
    cptestPrepareToDie();
    EXPECT_DEATH(Singleton::Consume<Example>::from<Example>(), "There is no single element from type '.*");
}

TEST(Singleton, HasObject)
{
    Example my_example;
    EXPECT_EQ(&my_example, Singleton::Consume<Example>::from<Example>());
}

TEST(Singleton, WasObject)
{
    cptestPrepareToDie();
    {
        Example my_example;
        EXPECT_EQ(&my_example, Singleton::Consume<Example>::from<Example>());
    }
    EXPECT_DEATH(Singleton::Consume<Example>::from<Example>(), "There is no single element from type '.*");
}

TEST(Singleton, CheckForObject)
{
    EXPECT_FALSE(Singleton::exists<Example>());
    {
        Example my_example;
        EXPECT_TRUE(Singleton::exists<Example>());
    }
    EXPECT_FALSE(Singleton::exists<Example>());
}

TEST(Singleton, DeathOnDoubleObject)
{
    cptestPrepareToDie();
    Example my_example;
    EXPECT_EQ(&my_example, Singleton::Consume<Example>::from<Example>());
    Example another_example;
    EXPECT_DEATH(Singleton::Consume<Example>::from<Example>(), "There is no single element from type '.*");
}

TEST(Singleton, ReturnToSingleObject)
{
    Example my_example;
    {
        // Temporary object
        Example another_example;
    }
    EXPECT_EQ(&my_example, Singleton::Consume<Example>::from<Example>());
}

class I_Interface
{
public:
    virtual int doSomething() = 0;
};

class ExampleInterface : public Singleton::Provide<I_Interface>::SelfInterface
{
public:
    int doSomething() override { return 5; }
};

class ExampleUser : public Singleton::Consume<I_Interface>
{
};

TEST(Singleton, HasInterfaceObject)
{
    ExampleInterface myExample;
    I_Interface *ptr = &myExample;
    EXPECT_EQ(Singleton::Consume<I_Interface>::from<MockProvider<I_Interface>>(), ptr);
    EXPECT_EQ((getInterface<ExampleInterface, I_Interface>()), ptr);
    EXPECT_EQ((getInterface<ExampleUser, I_Interface>()), ptr);
}

class I_AnotherInterface
{
public:
    virtual bool checkSomething() = 0;
};

class ExampleOwned : public I_AnotherInterface, public Singleton::OwnedSingleton
{
public:
    bool checkSomething() override { return true; }
};

TEST(Singleton, CheckForOwnedObject)
{
    EXPECT_FALSE(Singleton::existsOwned<ExampleOwned>());

    Singleton::newOwned<ExampleOwned>();
    EXPECT_TRUE(Singleton::existsOwned<ExampleOwned>());

    Singleton::deleteOwned<ExampleOwned>();
    EXPECT_FALSE(Singleton::existsOwned<ExampleOwned>());
}

class MockExampleOwned : public ExampleOwned
{
public:
    MOCK_METHOD0(checkSomething, bool());
};

TEST(Singleton, MockOwnedObject)
{
    auto ptr = make_unique<MockExampleOwned>();
    auto real_obj = ptr.get();

    EXPECT_FALSE(Singleton::existsOwned<ExampleOwned>());

    Singleton::setOwned<ExampleOwned>(move(ptr));
    EXPECT_TRUE(Singleton::existsOwned<ExampleOwned>());

    EXPECT_CALL(*real_obj, checkSomething());
    auto single_obj = Singleton::getOwned<ExampleOwned>();
    single_obj->checkSomething();

    Singleton::deleteOwned<ExampleOwned>();
    EXPECT_FALSE(Singleton::existsOwned<ExampleOwned>());
}

// Fixture to test provide/consume methods
// Contains a couple of dummy components, one provides an interface and one consumes it.
class SingletonCompTest : public Test
{
public:
    class I_Example {};
    class Provider;
    class Consumer;
};

class SingletonCompTest::Provider : Singleton::Provide<I_Example>
{
public:
    Provider() : pimpl(make_unique<Impl>()) {}
    ~Provider() {}

private:
    class Impl;
    unique_ptr<Impl> pimpl;
};

class SingletonCompTest::Provider::Impl
        :
    Singleton::Provide<I_Example>::From<Provider>
{
};

class SingletonCompTest::Consumer : Singleton::Consume<I_Example>
{
public:
    Consumer() : pimpl(make_unique<Impl>()) {}
    ~Consumer() {}

private:
    class Impl;
    unique_ptr<Impl> pimpl;
};

class SingletonCompTest::Consumer::Impl
{
public:
    Impl() : p(Singleton::Consume<I_Example>::by<Consumer>()) {}
    I_Example *p;
};

TEST_F(SingletonCompTest, provide)
{
    EXPECT_FALSE(Singleton::exists<I_Example>());

    {
        // Instantiate Provider to register a singleton
        Provider pro;
        EXPECT_TRUE(Singleton::exists<I_Example>());
    }

    EXPECT_FALSE(Singleton::exists<I_Example>());
}

TEST_F(SingletonCompTest, consume)
{
    Provider pro;

    // Consume the interface. Just see that it compiles and doesn't crash.
    Consumer con;
}

TEST_F(SingletonCompTest, consumeFrom)
{
    Provider pro;

    EXPECT_NE(nullptr, Singleton::Consume<I_Example>::from(pro));
}
