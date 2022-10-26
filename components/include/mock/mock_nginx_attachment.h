#ifndef __MOCK_NGINX_ATTACHMENT_H__
#define __MOCK_NGINX_ATTACHMENT_H__

#include "nginx_attachment.h"

class MockNginxAttachment:
        public Singleton::Provide<I_StaticResourcesHandler>::From<MockProvider<I_StaticResourcesHandler>>
{
public:
    MOCK_METHOD2(
        registerStaticResource,
        bool(const std::string &static_resource_name, const std::string &static_resource_path)
    );
};

#endif // __MOCK_NGINX_ATTACHMENT_H__
