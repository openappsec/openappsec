#include "ips_metric.h"

void
IPSSignatureSubTypes::IPSMetric::upon(const MatchEvent &event)
{
    switch (event.getAction()) {
        case SignatureAction::PREVENT: {
            prevented.report(1);
            break;
        }
        case SignatureAction::DETECT: {
            detected.report(1);
            break;
        }
        case SignatureAction::IGNORE: {
            ignored.report(1);
            break;
        }
    }
}
