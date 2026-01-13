#ifndef __INTELL_REGISTRATION_EVENT_H__
#define __INTELL_REGISTRATION_EVENT_H__

#include "event.h"

class IntelligenceRegistrationEvent : public Event<IntelligenceRegistrationEvent>
{
public:
    IntelligenceRegistrationEvent(bool registration_successful, std::string registration_response)
        :
        registration_successful(registration_successful),
        registration_response(registration_response)
    {}
    
    IntelligenceRegistrationEvent(bool registration_successful)
        :
        IntelligenceRegistrationEvent(registration_successful, "")
    {}
    
    bool isRegistrationSuccessful() const { return registration_successful; }
    std::string getRegistrationResponse() const { return registration_response; }

private:
    bool registration_successful;
    std::string registration_response;
};

#endif // __INTELL_REGISTRATION_EVENT_H__
