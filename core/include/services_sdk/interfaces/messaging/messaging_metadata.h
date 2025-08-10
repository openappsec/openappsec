#ifndef __MESSAGING_METADATA_H__
#define __MESSAGING_METADATA_H__

#include <map>
#include <string>

#include "flags.h"
#include "config.h"
#include "singleton.h"
#include "i_agent_details.h"
#include "i_time_get.h"
#include "i_environment.h"

class MessageProxySettings
{
public:
    MessageProxySettings() {}

    MessageProxySettings(const std::string &_proxy_host, const std::string &_proxy_auth, uint16_t _proxy_port)
            :
        proxy_host(_proxy_host), proxy_authentication(_proxy_auth), proxy_port(_proxy_port)
    {}

    const std::string &
    getProxyHost() const
    {
        return proxy_host;
    }

    const std::string &
    getProxyAuth() const
    {
        return proxy_authentication;
    }

    uint16_t
    getProxyPort() const
    {
        return proxy_port;
    }

    template <class Archive>
    void
    serialize(Archive &ar)
    {
        ar(
            cereal::make_nvp("proxy_host", proxy_host),
            cereal::make_nvp("proxy_authentication", proxy_authentication),
            cereal::make_nvp("proxy_port", proxy_port)
        );
    }

private:
    std::string proxy_host = "";
    std::string proxy_authentication = "";
    uint16_t proxy_port = 0;
};

class MessageMetadata : Singleton::Consume<I_TimeGet>, Singleton::Consume<I_Environment>
{
public:
    inline MessageMetadata(bool immediate_tracing = false);

    MessageMetadata(
        const std::string &_host_name,
        uint16_t _port_num,
        bool _buffer = false,
        bool _fog = false,
        bool immediate_tracing = false
    ) :
        host_name(_host_name),
        port_num(_port_num),
        should_buffer(_buffer),
        is_to_fog(_fog)
    {
        if (immediate_tracing && Singleton::exists<I_Environment>()) {
            insertHeaders(Singleton::Consume<I_Environment>::by<MessageMetadata>()->getCurrentHeadersMap());
        }
    }

    MessageMetadata(
        std::string _host_name,
        uint16_t _port_num,
        Flags<MessageConnectionConfig> _conn_flags,
        bool _should_buffer = false,
        bool _is_to_fog = false,
        bool _should_suspend = true,
        bool immediate_tracing = false
    ) :
        host_name(_host_name),
        port_num(_port_num),
        conn_flags(_conn_flags),
        should_buffer(_should_buffer),
        is_to_fog(_is_to_fog),
        should_send_access_token(true),
        should_suspend(_should_suspend)
    {
        if (immediate_tracing && Singleton::exists<I_Environment>()) {
            insertHeaders(Singleton::Consume<I_Environment>::by<MessageMetadata>()->getCurrentHeadersMap());
        }
    }

    const bool &
    shouldSendAccessToken() const
    {
        return should_send_access_token;
    }

    const std::string &
    getHostName() const
    {
        return host_name;
    }

    const uint16_t &
    getPort() const
    {
        return port_num;
    }

    void
    setShouldSendAccessToken(const bool &_should_send_access_token)
    {
        should_send_access_token = _should_send_access_token;
    }

    void
    setConnectioFlag(MessageConnectionConfig flag)
    {
        conn_flags.setFlag(flag);
    }

    const Flags<MessageConnectionConfig> &
    getConnectionFlags() const
    {
        return conn_flags;
    }

    const MessageProxySettings &
    getProxySettings() const
    {
        return proxy_settings;
    }

    const std::string &
    getExternalCertificate() const
    {
        return external_certificate;
    }

    const std::map<std::string, std::string> &
    getHeaders() const
    {
        return headers;
    }

    Maybe<std::string>
    getTraceId() const
    {
        auto trace_id = headers.find("X-Trace-Id");
        if (trace_id != headers.end()) return trace_id->second;
        return genError("Trace ID not found");
    }

    std::string
    getCaPath() const
    {
        if (!ca_path.empty()) return ca_path;
        return getConfigurationWithDefault(
            getFilesystemPathConfig() + "/certs/fog.pem",
            "message",
            "Certificate chain file path"
        );
    }

    const std::string &
    getClientCertPath() const
    {
        return client_cert_path;
    }

    const std::string &
    getClientKeyPath() const
    {
        return client_key_path;
    }

    void
    insertHeader(const std::string &header_key, const std::string &header_val)
    {
        headers[header_key] = header_val;
    }

    void
    insertHeaders(const std::map<std::string, std::string> &_headers)
    {
        headers.insert(_headers.begin(), _headers.end());
    }

    void
    setProxySettings(const MessageProxySettings &_proxy_settings)
    {
        proxy_settings = _proxy_settings;
        is_proxy_set = true;
    }

    void
    setCAPath (const std::string &_ca_path)
    {
        ca_path = _ca_path;
    }

    void
    setDualAuthenticationSettings
    (
        const std::string &_client_cert_path,
        const std::string &_client_key_path
    )
    {
        client_cert_path = _client_cert_path;
        client_key_path = _client_key_path;
        is_dual_auth = true;
    }

    void
    setSuspension(bool _should_suspend)
    {
        should_suspend = _should_suspend;
    }

    void
    setExternalCertificate(const std::string &_external_certificate)
    {
        external_certificate = _external_certificate;
    }

    void
    setShouldBufferMessage(bool _should_buffer)
    {
        should_buffer = _should_buffer;
    }

    bool
    shouldBufferMessage() const
    {
        return should_buffer;
    }

    bool
    shouldSuspend() const
    {
        return should_suspend;
    }

    bool
    isProxySet() const
    {
        return is_proxy_set;
    }

    bool
    isDualAuth() const
    {
        return is_dual_auth;
    }

    bool
    isToFog() const
    {
        return is_to_fog;
    }

    void
    setSniHostName(const std::string &_host_name)
    {
        sni_host_name = _host_name;
    }

    Maybe<std::string>
    getSniHostName() const
    {
        return sni_host_name;
    }

    void
    setDnHostName(const std::string &_dn_host_name)
    {
        dn_host_name = _dn_host_name;
    }

    Maybe<std::string>
    getDnHostName() const
    {
        return dn_host_name;
    }

    void
    setRateLimitBlock(uint block_time)
    {
        is_rate_limit_block = true;
        auto timer = Singleton::Consume<I_TimeGet>::by<MessageMetadata>();
        auto current_timeout = timer->getMonotonicTime() + std::chrono::seconds(block_time);
        rate_limit_block_time = current_timeout.count();
    }

    bool
    isRateLimitBlock() const
    {
        if (is_rate_limit_block) {
            auto timer = Singleton::Consume<I_TimeGet>::by<MessageMetadata>();
            uint current_time = timer->getMonotonicTime().count();
            if (current_time < rate_limit_block_time) return true;
        }
        return false;
    }

    template <class Archive>
    void
    serialize(Archive &ar)
    {
        ar(
            cereal::make_nvp("host_name", host_name),
            cereal::make_nvp("port_num", port_num),
            cereal::make_nvp("is_proxy_set", is_proxy_set),
            cereal::make_nvp("is_dual_auth", is_dual_auth),
            cereal::make_nvp("headers", headers),
            cereal::make_nvp("conn_flags", conn_flags),
            cereal::make_nvp("external_certificate", external_certificate),
            cereal::make_nvp("should_buffer", should_buffer),
            cereal::make_nvp("is_to_fog", is_to_fog),
            cereal::make_nvp("ca_path", ca_path),
            cereal::make_nvp("client_cert_path", client_cert_path),
            cereal::make_nvp("client_key_path", client_key_path),
            cereal::make_nvp("is_rate_limit_block", is_rate_limit_block),
            cereal::make_nvp("rate_limit_block_time", rate_limit_block_time)
        );
    }

private:
    std::string host_name = "";
    Maybe<std::string> sni_host_name = genError("SNI host name not set");
    Maybe<std::string> dn_host_name = genError("DN host name not set");
    std::string ca_path = "";
    std::string client_cert_path = "";
    std::string client_key_path = "";
    uint16_t port_num = 0;
    bool is_proxy_set = false;
    bool is_dual_auth = false;
    std::map<std::string, std::string> headers;
    Flags<MessageConnectionConfig> conn_flags;
    MessageProxySettings proxy_settings;
    std::string external_certificate = "";
    bool should_buffer = false;
    bool is_to_fog = false;
    bool is_rate_limit_block = false;
    uint rate_limit_block_time = 0;
    bool should_send_access_token = true;
    bool should_suspend = true;
};

#endif // __MESSAGING_METADATA_H__
