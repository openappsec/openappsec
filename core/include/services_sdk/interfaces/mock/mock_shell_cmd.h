#ifndef __MOCK_SHELL_CMD_H__
#define __MOCK_SHELL_CMD_H__

#include <gmock/gmock.h>

#include "i_shell_cmd.h"
#include "singleton.h"
#include "cptest.h"

static std::ostream &
operator<<(std::ostream &os, const Maybe<std::pair<std::string, int>> &val)
{
    if (val.ok()) return os << "<" << (*val).first << ", " << (*val).second << ">";
    return os;
}

class MockShellCmd : public Singleton::Provide<I_ShellCmd>::From<MockProvider<I_ShellCmd>>
{
public:
    MOCK_METHOD3(getExecOutput, Maybe<std::string>(const std::string &cmd, uint tmout, bool do_yield));
    MOCK_METHOD3(getExecReturnCode, Maybe<int>(const std::string &cmd, uint tmout, bool do_yield));
    MOCK_METHOD3(getExecOutputAndCode, Maybe<std::pair<std::string, int>>(const std::string &, uint, bool));
};

#endif // __MOCK_SHELL_CMD_H__
