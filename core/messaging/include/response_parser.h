#ifndef __RESPONSE_PARSER_H__
#define __RESPONSE_PARSER_H__

#include "i_messaging.h"

class HTTPResponseParser
{
public:
    Maybe<HTTPResponse> parseData(const std::string &data, bool is_connect);

    bool
    hasReachedError() const
    {
        return error;
    }

private:
    bool parseStatusLine();
    bool handleHeaders();
    bool handleBody(bool is_connect);

    Maybe<std::string> getHeaderVal(const std::string &header_key);

    bool getChunkedResponse();
    bool isLegalChunkedResponse(const std::string &res);

    Maybe<HTTPStatusCode> status_code = genError("Not received");
    Maybe<std::map<std::string, std::string>> headers = genError("Not received");
    std::string body;
    std::string raw_response;
    bool error = false;
};

#endif // __RESPONSE_PARSER_H__
