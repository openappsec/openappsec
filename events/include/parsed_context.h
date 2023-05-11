#ifndef __PARSED_CONTEXT_H__
#define __PARSED_CONTEXT_H__

#include <string>

#include "event.h"
#include "buffer.h"

enum class ParsedContextReply { ACCEPT, DROP };

class ParsedContext : public Event<ParsedContext, ParsedContextReply>
{
public:
    ParsedContext(const Buffer &_buf, const std::string &_name, uint _id) : buf(_buf), name(_name), id(_id) {}
    const Buffer & getBuffer() const { return buf; }
    const std::string & getName() const { return name; }
    uint getId() const  { return id; }

private:
    Buffer buf;
    std::string name;
    uint id;
};

#endif // __PARSED_CONTEXT_H__
