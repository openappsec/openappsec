#ifndef __NGINX_MESSAGE_READER_H__
#define __NGINX_MESSAGE_READER_H__

#include "singleton.h"
#include "i_mainloop.h"
#include "i_socket_is.h"
#include "component.h"

class NginxMessageReader
        :
    public Component,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_Socket>
{
public:
    NginxMessageReader();
    ~NginxMessageReader();

    void init() override;
    void fini() override;
    void preload() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif //__NGINX_MESSAGE_READER_H__
