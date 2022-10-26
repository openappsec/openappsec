#include <string>
#include <sstream>
#include <iostream>

#include "pending_key.h"
#include "cptest.h"

using namespace std;
using namespace testing;

class PendingKeyTest : public Test
{
protected:

    PendingKey
    get_pkey(string src_ip, string dst_ip, PortNumber d_port, IPProto ip_p)
    {
        return PendingKey(IPAddr::createIPAddr(src_ip).unpack(), IPAddr::createIPAddr(dst_ip).unpack(), d_port, ip_p);
    }

    virtual void
    SetUp()
    {
        cptestPrepareToDie();
        ck_v4 = get_pkey("1.1.1.1", "2.2.2.2", 80, 6);
        ck_v6 = get_pkey("2000::1", "3000::2", 53, 17);
    }

    virtual void
    TearDown()
    {
    }

public:
    PendingKey ck_v4;
    PendingKey ck_v6;
};


TEST_F(PendingKeyTest, equality_v4)
{
    EXPECT_EQ(ck_v4, ck_v4);
}

TEST_F(PendingKeyTest, equality_v6)
{
    EXPECT_EQ(ck_v6, ck_v6);
}

TEST_F(PendingKeyTest, equality_mixed_versions)
{
    EXPECT_NE(ck_v4, ck_v6);
}

TEST_F(PendingKeyTest, equality_mixed_versions_same_fields)
{
    PendingKey zero4 = get_pkey("0.0.0.0", "0.0.0.0", 0, 17);
    PendingKey zero6 = get_pkey("0::0",    "0::0",    0, 17);
    EXPECT_NE(zero4, zero6);
}

TEST_F(PendingKeyTest, equality_diff_only_in_ip)
{
    PendingKey k1 = get_pkey("1.1.1.1", "2.2.2.2", 0, 17);
    PendingKey k2 = get_pkey("1.1.1.1", "3.3.3.3", 0, 17);
    PendingKey k3 = get_pkey("4.4.4.4", "2.2.2.2", 0, 17);
    EXPECT_NE(k1, k2);
    EXPECT_NE(k1, k3);
    EXPECT_NE(k2, k3);
}

TEST_F(PendingKeyTest, equality_diff_only_in_port)
{
    PendingKey k1 = get_pkey("1.1.1.1", "2.2.2.2", 1, 17);
    PendingKey k2 = get_pkey("1:1::1",  "2:2::2",  1, 17);
    PendingKey k3 = get_pkey("1.1.1.1", "2.2.2.2", 2, 17);
    PendingKey k4 = get_pkey("1:1::1",  "2:2::2",  2, 17);
    EXPECT_NE(k1, k3);
    EXPECT_NE(k2, k4);
}

TEST_F(PendingKeyTest, equality_diff_only_in_proto)
{
    PendingKey k1 = get_pkey("1.1.1.1", "2.2.2.2", 2, 6);
    PendingKey k2 = get_pkey("1.1.1.1", "2.2.2.2", 2, 17);
    EXPECT_NE(k1, k2);
}

TEST_F(PendingKeyTest, copy_operator)
{
    PendingKey ck4_copy = ck_v4;
    PendingKey ck6_copy = ck_v6;
    EXPECT_EQ(ck4_copy, ck_v4);
    EXPECT_EQ(ck6_copy, ck_v6);
}

TEST_F(PendingKeyTest, hash)
{
    PendingKey copy_v4 = ck_v4;
    PendingKey copy_v6 = ck_v6;
    EXPECT_EQ(copy_v4.hash(), ck_v4.hash());
    EXPECT_EQ(copy_v6.hash(), ck_v6.hash());
}

TEST_F(PendingKeyTest, formatting_v4)
{
    EXPECT_EQ(ToString(ck_v4),     "<1.1.1.1 -> 2.2.2.2|80 6>");
}

TEST_F(PendingKeyTest, formatting_v6)
{
    string expected_str = "<2000::1 -> 3000::2|53 17>";
    EXPECT_EQ(ToString(ck_v6), expected_str);

    PendingKey src_extra_zeros = get_pkey("2000:0::0:1", "3000::2", 53, 17);
    EXPECT_EQ(ToString(src_extra_zeros), expected_str);
}

TEST_F(PendingKeyTest, formatting_no_ports)
{
    // Port number not printed for non-TCP/UDP (whether its zero or not)
    PendingKey proto123 = get_pkey("2000:0::0:1", "3000::2", 0, 123);
    PendingKey proto123_ports = get_pkey("2000:0::0:1", "3000::2", 333, 123);
    EXPECT_EQ(ToString(proto123),       "<2000::1 -> 3000::2 123>");
    EXPECT_NE(ToString(proto123_ports), "<2000::1 -> 3000::2|333 123>");

    // Port number printed for TCP/UDP, even if its zero
    PendingKey port0 = get_pkey("1.1.1.1", "2.2.2.2", 0, 6);
    EXPECT_EQ(ToString(port0), "<1.1.1.1 -> 2.2.2.2|0 6>");
}

TEST_F(PendingKeyTest, death_hash_on_uninit)
{
    cptestPrepareToDie();
    PendingKey uninit;
    EXPECT_DEATH(uninit.hash(), "PendingKey::hash was called on an uninitialized object");
}

TEST_F(PendingKeyTest, death_eqaulity_on_uninit)
{
    PendingKey uninit;
    EXPECT_DEATH((void)(uninit == uninit), "Called on an uninitialized IPType object");
}
