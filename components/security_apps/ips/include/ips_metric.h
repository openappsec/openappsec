#ifndef __IPS_METRIC_H__
#define __IPS_METRIC_H__

#include "ips_signatures.h"
#include "generic_metric.h"

namespace IPSSignatureSubTypes
{

class MatchEvent : public Event<MatchEvent>
{
public:
    MatchEvent(const std::shared_ptr<CompleteSignature> &sig, SignatureAction act) : signature(sig), action(act) {}

    const SignatureAction & getAction() const { return action; }

private:
    std::shared_ptr<CompleteSignature> signature;
    SignatureAction action;
};

class IPSMetric : public GenericMetric, public Listener<MatchEvent>
{
public:
    void upon(const MatchEvent &event) override;

private:
    MetricCalculations::Counter prevented{this, "preventEngineMatchesSample"};
    MetricCalculations::Counter detected{this, "detectEngineMatchesSample"};
    MetricCalculations::Counter ignored{this, "ignoreEngineMatchesSample"};
};

} // IPSSignatureSubTypes

#endif // __IPS_METRIC_H__
