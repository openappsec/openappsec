#include "event.h"
#include "listener.h"

#include <string>

#include "cptest.h"

using namespace std;
using namespace testing;

class IntEvent : public Event<IntEvent>
{
public:
    IntEvent(int _i) : i(_i) {}

    int i;
};

class IntEventReturnInt : public Event<IntEventReturnInt, int>
{
public:
    IntEventReturnInt(int _i) : i(_i) {}

    int i;
};

class IntEventReturnString: public Event<IntEventReturnString, string>
{
public:
    IntEventReturnString(int _i) : i(_i) {}

    int i;
};

class StringEvent : public Event<StringEvent>
{
public:
    StringEvent(const string &_s) : s(_s) {}

    string s;
};

class IntEventListener : public Listener<IntEvent>
{
public:
    void upon(const IntEvent &event) override { i = event.i; }

    int i = 0;
};

class IntEventReturnIntListener : public Listener<IntEventReturnInt>
{
public:
    IntEventReturnIntListener(int _r) : r(_r) {}

    string getListenerName() const override { return "IntEventReturnIntListener"; }

    void upon(const IntEventReturnInt &event) override { i = event.i; }
    int respond(const IntEventReturnInt &event) override { j = event.i; return r; }

    int i = 0, j = 0, r;
};

class IntEventReturnStringListener : public Listener<IntEventReturnString>
{
public:
    IntEventReturnStringListener(const string &_r) : r(_r) {}

    string getListenerName() const override { return "IntEventReturnStringListener"; }

    void upon(const IntEventReturnString &event) override { i = event.i; }
    string respond(const IntEventReturnString &event) override { j = event.i; return r; }

    int i = 0, j = 0;
    string r;
};

class StringEventListener : public Listener<StringEvent>
{
public:
    void upon(const StringEvent&event) override { s = event.s; }

    string s;
};

class DualListener : public Listener<IntEventReturnInt>, public Listener<IntEventReturnString>
{
public:
    DualListener(int i_r, const string &s_r) : return_int(i_r), return_string(s_r) {}

    string getListenerName() const override { return "DualListener"; }

    void upon(const IntEventReturnInt &event) override { notify_int = event.i; }
    int respond(const IntEventReturnInt &event) override { query_int = event.i; return return_int; }

    void upon(const IntEventReturnString &event) override { notify_string = event.i; }
    string respond(const IntEventReturnString &event) override { query_string = event.i; return return_string; }

    int notify_int = 0, query_int = 0;
    int notify_string = 0, query_string = 0;
    int return_int;
    string return_string;
};

TEST(Event, basic)
{
    IntEventListener listen1;

    IntEvent event1(7);

    event1.notify();
    EXPECT_EQ(listen1.i, 0);

    listen1.registerListener();
    event1.notify();
    EXPECT_EQ(listen1.i, 7);
    listen1.i = 0;

    listen1.unregisterListener();
    event1.notify();
    EXPECT_EQ(listen1.i, 0);
}

TEST(Event, multiple_listeners)
{
    IntEventListener listen1;
    listen1.registerListener();
    IntEventListener listen2;
    listen2.registerListener();
    IntEventListener listen3;
    listen3.registerListener();

    IntEvent event1(7);
    event1.notify();

    EXPECT_EQ(listen1.i, 7);
    EXPECT_EQ(listen2.i, 7);
    EXPECT_EQ(listen3.i, 7);
}

TEST(Event, multiple_events)
{
    IntEventListener listen1;
    listen1.registerListener();

    IntEvent event1(7);
    event1.notify();
    EXPECT_EQ(listen1.i, 7);

    IntEvent event2(34);
    event2.notify();
    EXPECT_EQ(listen1.i, 34);

    IntEvent event3(18);
    event3.notify();
    EXPECT_EQ(listen1.i, 18);

    event1.i = 9;
    event1.notify();
    EXPECT_EQ(listen1.i, 9);
}

TEST(Event, different_event_types)
{
    IntEventListener listen1;
    listen1.registerListener();
    StringEventListener listen2;
    listen2.registerListener();

    IntEvent event1(7);
    StringEvent event2("22");

    EXPECT_EQ(listen1.i, 0);
    EXPECT_EQ(listen2.s, "");

    event1.notify();
    EXPECT_EQ(listen1.i, 7);
    EXPECT_EQ(listen2.s, "");

    event2.notify();
    EXPECT_EQ(listen1.i, 7);
    EXPECT_EQ(listen2.s, "22");
}

TEST(Event, basic_event_with_return_type)
{
    IntEventReturnIntListener listen1(2);
    listen1.registerListener();
    IntEventReturnInt event1(8);
    IntEventReturnInt event2(5);


    EXPECT_EQ(listen1.i, 0);
    EXPECT_EQ(listen1.j, 0);

    event1.notify();
    EXPECT_EQ(listen1.i, 8);
    EXPECT_EQ(listen1.j, 0);

    EXPECT_THAT(event2.query(), UnorderedElementsAre(2));
    EXPECT_EQ(listen1.i, 8);
    EXPECT_EQ(listen1.j, 5);
}

TEST(Event, multiple_return_listeners)
{
    IntEventReturnIntListener listen1(2);
    listen1.registerListener();
    IntEventReturnIntListener listen2(75);
    listen2.registerListener();

    IntEventReturnInt event1(8);
    EXPECT_THAT(event1.query(), UnorderedElementsAre(2, 75));
}

TEST(Event, dual_listener)
{
    DualListener listen(15, "ther");
    listen.registerListener();

    IntEventReturnInt event1(8);

    event1.notify();
    EXPECT_EQ(listen.notify_int, 8);

    EXPECT_THAT(event1.performNamedQuery(), ElementsAre(Pair("DualListener", 15)));
    EXPECT_EQ(listen.query_int, 8);


    IntEventReturnString event2(13);

    event2.notify();
    EXPECT_EQ(listen.notify_string, 13);

    EXPECT_THAT(event2.query(), ElementsAre("ther"));
    EXPECT_EQ(listen.query_string, 13);

    listen.unregisterListener();

    EXPECT_THAT(event1.query(), ElementsAre());
    EXPECT_THAT(event2.performNamedQuery(), ElementsAre());
}
