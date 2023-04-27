#ifndef __MOCK_MAINLOOP_H__
#define __MOCK_MAINLOOP_H__

#include "i_mainloop.h"
#include "singleton.h"
#include "cptest.h"

class MockMainLoop : public Singleton::Provide<I_MainLoop>::From<MockProvider<I_MainLoop>>
{
public:
    MOCK_METHOD4(addOneTimeRoutine,         uint (RoutineType, Routine, const std::string &, bool));

    MOCK_METHOD5(
        addRecurringRoutine,
        uint (RoutineType, std::chrono::microseconds, Routine, const std::string &, bool)
    );

    MOCK_METHOD5(
        addFileRoutine,
        uint (RoutineType, int, Routine, const std::string &, bool)
    );

    MOCK_METHOD0(run,                       void ());

    MOCK_METHOD1(doesRoutineExist,          bool (RoutineID id));

    MOCK_CONST_METHOD0(getCurrentRoutineId, Maybe<I_MainLoop::RoutineID> ());

    MOCK_METHOD1(updateCurrentStress,       void (bool));

    MOCK_METHOD1(yield,                     void (bool));
    MOCK_METHOD1(yield,                     void (std::chrono::microseconds));

    MOCK_METHOD0(stopAll,                   void ());
    MOCK_METHOD0(stop,                      void ());
    MOCK_METHOD1(stop,                      void (uint));
    MOCK_METHOD0(halt,                      void ());
    MOCK_METHOD1(halt,                      void (uint));

    MOCK_METHOD1(resume,                    void (uint));
};

#endif // __MOCK_MAINLOOP_H__
