#ifndef ___SENTINEL_RUNTIME_STATE_H__
#define ___SENTINEL_RUNTIME_STATE_H__

#include "single_keyword.h"

class SentinelRuntimeState : public I_KeywordRuntimeState
{
public:
    uint getOffset(const std::string &) const override;
    uint getVariable(uint) const override;
};

#endif //  ___SENTINEL_RUNTIME_STATE_H__
