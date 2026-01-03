#ifndef __MOCK_NGINX_ATTACHMENT_H__
#define __MOCK_NGINX_ATTACHMENT_H__

#include "nginx_attachment.h"

class MockNginxAttachment:
        public Singleton::Provide<I_StaticResourcesHandler>::From<MockProvider<I_StaticResourcesHandler>>
{
public:
    MOCK_METHOD3(
        registerStaticResource,
        bool(const std::string &static_resource_name,
            const std::string &static_resource_path,
            bool overwrite_if_exists
        )
    );

    MOCK_METHOD2(
        registerStaticResourceByContent,
        bool(const std::string &resource_name, const std::string &file_content)
    );
};

#endif // __MOCK_NGINX_ATTACHMENT_H__
