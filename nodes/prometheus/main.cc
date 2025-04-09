#include "components_list.h"
#include "prometheus_comp.h"

int
main(int argc, char **argv)
{
    NodeComponents<PrometheusComp> comps;

    comps.registerGlobalValue<bool>("Is Rest primary routine", true);
    comps.registerGlobalValue<uint>("Nano service API Port Primary", 7465);
    comps.registerGlobalValue<uint>("Nano service API Port Alternative", 7466);
    comps.registerGlobalValue<bool>("Nano service API Allow Get From External IP", true);

    return comps.run("Prometheus Service", argc, argv);
}
