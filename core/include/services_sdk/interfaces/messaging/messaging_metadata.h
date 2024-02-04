#ifndef __MESSAGING_METADATA_H__
#define __MESSAGING_METADATA_H__

#include <map>
#include <string>

#include "flags.h"
#include "singleton.h"
#include "i_agent_details.h"

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

class MessageMetadata
{
public:
    inline MessageMetadata();

    MessageMetadata(const std::string &_host_name, uint16_t _port_num, bool _buffer = false, bool _fog = false) :
        host_name(_host_name), port_num(_port_num), should_buffer(_buffer), is_to_fog(_fog)
    {}

    MessageMetadata(
        std::string _host_name,
        uint16_t _port_num,
        Flags<MessageConnectionConfig> _conn_flags,
        bool _should_buffer = false,
        bool _is_to_fog = false
    ) :
        host_name(_host_name),
        port_num(_port_num),
        conn_flags(_conn_flags),
        should_buffer(_should_buffer),
        is_to_fog(_is_to_fog)
    {}

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
    isProxySet() const
    {
        return is_proxy_set;
    }

    bool
    isToFog() const
    {
        return is_to_fog;
    }

    template <class Archive>
    void
    serialize(Archive &ar)
    {
        ar(
            cereal::make_nvp("host_name", host_name),
            cereal::make_nvp("port_num", port_num),
            cereal::make_nvp("is_proxy_set", is_proxy_set),
            cereal::make_nvp("headers", headers),
            cereal::make_nvp("conn_flags", conn_flags),
            cereal::make_nvp("external_certificate", external_certificate),
            cereal::make_nvp("should_buffer", should_buffer),
            cereal::make_nvp("is_to_fog", is_to_fog)
        );
    }

private:
    std::string host_name = "";
    uint16_t port_num = 0;
    bool is_proxy_set = false;
    std::map<std::string, std::string> headers;
    Flags<MessageConnectionConfig> conn_flags;
    MessageProxySettings proxy_settings;
    std::string external_certificate = "";
    bool should_buffer = false;
    bool is_to_fog = false;
};

#endif // __MESSAGING_METADATA_H__
