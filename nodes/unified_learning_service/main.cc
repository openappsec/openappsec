#include "components_list.h"
#include "unified_learning_comp.h"

int
main(int argc, char **argv)
{
    NodeComponents<UnifiedLearningComponent> comps;

    // Configure as a background service
    comps.registerGlobalValue<bool>("Is Rest primary routine", false);
    comps.registerGlobalValue<uint>("Nano service API Port Primary", 4020);
    comps.registerGlobalValue<uint>("Nano service API Port Alternative", 4021);

    return comps.run("Unified Learning Service", argc, argv);
}
