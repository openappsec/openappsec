#ifndef __MOCK_CPU_H__
#define __MOCK_CPU_H__

#include "i_cpu.h"
#include "singleton.h"
#include "cptest.h"

class MockCPU : public Singleton::Provide<I_CPU>::From<MockProvider<I_CPU>>
{
public:
    MOCK_METHOD0(getCurrentProcessCPUUsage, double());
    MOCK_METHOD0(getCurrentGeneralCPUUsage, Maybe<double>());
};

#endif // __MOCK_CPU_H__
