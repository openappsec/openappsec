#include "rest.h"
#include "shell_cmd.h"
#include "rest_server.h"
#include "cptest.h"
#include "singleton.h"
#include "mainloop.h"
#include "encryptor.h"
#include "i_messaging.h"
#include "messaging.h"
#include "time_proxy.h"
#include "environment.h"
#include "config.h"
#include "config_component.h"
#include "agent_details.h"
#include "instance_awareness.h"
#include "tenant_manager.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include "customized_cereal_map.h"
#include "customized_cereal_multimap.h"
#include "mock/mock_agent_details.h"

using namespace std;

class MustInt : public ServerRest
{
    void doCall() override {}

    C2S_PARAM(int, must_int);
};

TEST(RestSchema, must_int)
{
    stringstream schema;
    MustInt().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_int\": {\n"
        "            \"type\": \"integer\"\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_int\"\n"
        "    ]\n"
        "}"
    );
}

class MustBool : public ServerRest
{
    void doCall() override {}

    C2S_PARAM(bool, must_bool);
};


TEST(RestSchema, must_bool)
{
    stringstream schema;
    MustBool().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_bool\": {\n"
        "            \"type\": \"boolean\"\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_bool\"\n"
        "    ]\n"
        "}"
    );
}

class MustString : public ServerRest
{
    void doCall() override {}

    C2S_PARAM(string, must_string);
};

TEST(RestSchema, must_string)
{
    stringstream schema;
    MustString().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_string\": {\n"
        "            \"type\": \"string\"\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_string\"\n"
        "    ]\n"
        "}"
    );
}

class MustVectorInt : public ServerRest
{
    void doCall() override {}

    C2S_PARAM(vector<int>, must_vector);
};

TEST(RestSchema, must_vector)
{
    stringstream schema;
    MustVectorInt().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_vector\": {\n"
        "            \"type\": \"array\",\n"
        "            \"items\": {\n"
        "                \"type\": \"integer\"\n"
        "            }\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_vector\"\n"
        "    ]\n"
        "}"
    );
}

class MustSetString :  public ServerRest
{
    void doCall() override {}

    C2S_PARAM(set<string>, must_set);
};

TEST(RestSchema, must_set)
{
    stringstream schema;
    MustSetString().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_set\": {\n"
        "            \"type\": \"array\",\n"
        "            \"items\": {\n"
        "                \"type\": \"string\"\n"
        "            }\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_set\"\n"
        "    ]\n"
        "}"
    );
}

class MustMapString :  public ServerRest
{
    void doCall() override {}

    using mapStringString = map<string, string>;
    C2S_PARAM(mapStringString, must_map_string);
};

class MustMapInt :  public ServerRest
{
    void doCall() override {}

    using mapStringInt = map<string, int>;
    C2S_PARAM(mapStringInt, must_map_int);
};

class MustMultiMap :  public ServerRest
{
    void doCall() override {}

    using mapStringInt = SerializableMultiMap<string, int>;
    C2S_PARAM(mapStringInt, must_multimap);
};

TEST(RestSchema, must_map)
{
    stringstream string_map_schema;
    MustMapString().performOutputingSchema(string_map_schema);
    EXPECT_EQ(
        string_map_schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_map_string\": {\n"
        "            \"type\": \"object\",\n"
        "            \"additionalProperties\": {\n"
        "                \"type\": \"string\"\n"
        "            }\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_map_string\"\n"
        "    ]\n"
        "}"
    );

    stringstream int_map_schema;
    MustMapInt().performOutputingSchema(int_map_schema);
    EXPECT_EQ(
        int_map_schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_map_int\": {\n"
        "            \"type\": \"object\",\n"
        "            \"additionalProperties\": {\n"
        "                \"type\": \"integer\"\n"
        "            }\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_map_int\"\n"
        "    ]\n"
        "}"
    );

    stringstream multi_map_schema;
    MustMultiMap().performOutputingSchema(multi_map_schema);
    EXPECT_EQ(
        multi_map_schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_multimap\": {\n"
        "            \"type\": \"object\",\n"
        "            \"additionalProperties\": {\n"
        "                \"anyOf\": [\n"
        "                    {\n"
        "                        \"type\": \"string\"\n"
        "                    },\n"
        "                    {\n"
        "                        \"type\": \"integer\"\n"
        "                    }\n"
        "                ]\n"
        "            }\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_multimap\"\n"
        "    ]\n"
        "}"
    );
}

class MustObject : public ServerRest
{
    void doCall() override {}

    C2S_PARAM(MustInt, must_object);
};

TEST(RestSchema, must_object)
{
    stringstream schema;
    MustObject().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_object\": {\n"
        "            \"type\": \"object\",\n"
        "            {\n"
        "                \"properties\": {\n"
        "                    \"must_int\": {\n"
        "                        \"type\": \"integer\"\n"
        "                    }\n"
        "                },\n"
        "                \"required\": [\n"
        "                    \"must_int\"\n"
        "                ]\n"
        "            }\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_object\"\n"
        "    ]\n"
        "}"
    );
}

class OptionalInt: public ServerRest
{
    void doCall() override {}

    C2S_OPTIONAL_PARAM(int, optional_int);
};

TEST(RestSchema, optional_int)
{
    stringstream schema;
    OptionalInt().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"optional_int\": {\n"
        "            \"type\": \"integer\"\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "    ]\n"
        "}"
    );
}

class DefaultInt : public ServerRest
{
    void doCall() override {}

    C2S_OPTIONAL_PARAM(int, default_int);
};

TEST(RestSchema, default_int)
{
    stringstream schema;
    DefaultInt().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"default_int\": {\n"
        "            \"type\": \"integer\"\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "    ]\n"
        "}"
    );
}

class MustLabelInt : public ServerRest
{
    void doCall() override {}

    C2S_LABEL_PARAM(int, must_int, "must-int");
};

TEST(RestSchema, must_int_label)
{
    stringstream schema;
    MustLabelInt().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must-int\": {\n"
        "            \"type\": \"integer\"\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must-int\"\n"
        "    ]\n"
        "}"
    );
}

class BothSidesInt : public ServerRest
{
public:
    void doCall() override { }

    BOTH_PARAM(int, must_int);
};

TEST(RestSchema, both_must_int)
{
    stringstream schema;
    BothSidesInt().performOutputingSchema(schema);
    EXPECT_EQ(
        schema.str(),
        "{\n"
        "    \"properties\": {\n"
        "        \"must_int\": {\n"
        "            \"type\": \"integer\"\n"
        "        }\n"
        "    },\n"
        "    \"required\": [\n"
        "        \"must_int\"\n"
        "    ]\n"
        "}"
    );
}

TEST(RestSchema, copy_constructor)
{
    BothSidesInt orig;
    orig.must_int = 99;
    BothSidesInt copy(orig);
    EXPECT_EQ(copy.must_int, 99);
}

class TypedSchema : public ClientRest
{
public:
    S2C_PARAM(string, type);
};

class ProperitiesSchema : public ClientRest
{
public:
    S2C_PARAM(TypedSchema, must_int);
};

class GetSchema : public ClientRest
{
public:
    S2C_PARAM(vector<string>, required);
    S2C_PARAM(ProperitiesSchema, properties);
};

TEST(RestSchema, server_schema)
{
    Debug::setUnitTestFlag(D_MESSAGING, Debug::DebugLevel::TRACE);
    ::Environment env;
    TimeProxyComponent time_proxy;
    MainloopComponent mainloop_comp;
    Encryptor encryptor;
    InstanceAwareness instance_awareness;
    ShellCmd cmd;
    I_Messaging *i_message;
    Messaging message;
    RestServer server;
    ConfigComponent config;
    TenantManager tenant_manager;
    testing::NiceMock<MockAgentDetails> mock_agent_details;


    env.preload();
    Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Base Executable Name", "tmp_test_file");

    config.preload();
    config.init();
    EXPECT_CALL(mock_agent_details, getAccessToken()).WillRepeatedly(testing::Return(string("accesstoken")));
    EXPECT_CALL(mock_agent_details, getFogDomain()).WillRepeatedly(testing::Return(string("127.0.0.1")));
    EXPECT_CALL(mock_agent_details, getFogPort()).WillRepeatedly(testing::Return(9777));

    string config_json =
        "{"
        "   \"agentSettings\": [\n"
        "   {\n"
        "       \"id\": \"123\",\n"
        "       \"key\": \"eventBuffer.maxSizeOnDiskInMB\",\n"
        "       \"value\": \"1\"\n"
        "   },\n"
        "   {\n"
        "       \"id\": \"123\",\n"
        "       \"key\": \"eventBuffer.baseFolder\",\n"
        "       \"value\": \"/test_data/\"\n"
        "   }]\n"
        "}";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);
    setConfiguration(false, string("message"), string("HTTPS connection"));
    setConfiguration(uint(9777), string("connection"), string("Nano service API Port Primary"));
    setConfiguration(uint(9778), string("connection"), string("Nano service API Port Alternative"));
    message.init();


    server.init();
    cmd.init();
    time_proxy.init();
    mainloop_comp.init();
    auto api = Singleton::Consume<I_RestApi>::from(server);
    api->addRestCall<BothSidesInt>(RestAction::ADD, "int");

    auto mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);

    bool stop = false;
    I_MainLoop::Routine stop_routine = [&stop, mainloop] () {
        while (!stop) {
            mainloop->yield(true);
        }

        for (uint i = 0; i < 26; i++) {
            mainloop->yield(true);
        }

        mainloop->stopAll();
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        stop_routine,
        "RestSchema server_schema stop routine",
        true
    );

    i_message = Singleton::Consume<I_Messaging>::from(message);
    I_MainLoop::Routine action = [&stop, i_message] () {
        GetSchema schema;
        Flags<MessageConnectionConfig> conn_flags;
        conn_flags.setFlag(MessageConnectionConfig::ONE_TIME_CONN);
        MessageMetadata message_metadata("127.0.0.1", 9777, conn_flags);
        message_metadata.setConnectioFlag(MessageConnectionConfig::UNSECURE_CONN);
        auto is_message_sent = i_message->sendSyncMessage(
            HTTPMethod::GET,
            "/add-int",
            schema,
            MessageCategory::GENERIC,
            message_metadata
        );
        EXPECT_TRUE(is_message_sent.ok());
        vector<string> expected_req = { "must_int" };
        EXPECT_EQ(schema.required.get(), expected_req);
        ProperitiesSchema properties(schema.properties.get());
        TypedSchema must_int(properties.must_int.get());
        EXPECT_EQ(must_int.type.get(), "integer");
        stop = true;
    };
    mainloop->addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, action, "RestSchema server_schema action routine");

    mainloop->run();
    server.fini();
    cmd.fini();
    time_proxy.fini();
    mainloop_comp.fini();
}

TEST(RestSchema, short_connection_server)
{
    TimeProxyComponent time_proxy;
    AgentDetails agent_details;
    MainloopComponent mainloop_comp;
    ::Environment env;
    RestServer server;
    ConfigComponent config;
    server.preload();
    env.init();
    time_proxy.init();

    setConfiguration<uint>(uint(9777), string("connection"), string("Nano service API Port Range start"));
    setConfiguration<uint>(uint(9778), string("connection"), string("Nano service API Port Range end"));

    Singleton::Consume<I_Environment>::from(env)->registerValue<bool>("Is Rest primary routine", true);
    server.init();

    auto mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);

    bool stop = false;
    I_MainLoop::Routine stop_routine = [&stop, mainloop] () {
        while (!stop) {
            mainloop->yield(true);
        }

        for (uint i = 0; i < 16; i++) {
            mainloop->yield(true);
        }

        mainloop->stopAll();
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        stop_routine,
        "RestSchema short_connection_server stop routine",
        true
    );

    I_MainLoop::Routine action = [&] () {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return;
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_port = htons(9777);
        sa.sin_addr.s_addr = inet_addr("127.0.0.1");
        mainloop->yield(true);
        if (connect(fd, (struct sockaddr*)&sa, sizeof(struct sockaddr)) < 0) {
            close(fd);
            return;
        }
        close(fd);
        stop = true;
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        action,
        "RestSchema short_connection_server action routine"
    );

    mainloop->run();
    server.fini();
    time_proxy.fini();
    mainloop_comp.fini();
}
