// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __NODE_COMPONENTS_IMPL_H__
#define __NODE_COMPONENTS_IMPL_H__

#ifndef __COMPONENTS_LIST_H__
#error node_components_impl.h should not be included directly!
#endif // __COMPONENTS_LIST_H__

template <typename ... Components>
int
NodeComponents<Components...>::run(const std::string &nano_service_name, int argc, char **argv)
{
    std::vector<std::string> arg_vec(argv, argv+argc);

    try {
        Infra::ComponentListCore<Components...>::handleArgs(arg_vec);

        Infra::ComponentListCore<Components...>::preloadComponents(nano_service_name);
        Infra::ComponentListCore<Components...>::loadConfiguration(arg_vec);

        Infra::ComponentListCore<Components...>::init();
        Infra::ComponentListCore<Components...>::run(nano_service_name);
        Infra::ComponentListCore<Components...>::fini();
    } catch (const Infra::ComponentListException &comp_exception) {
        if (comp_exception.getIsError()) {
            std::cerr << "Error: " << comp_exception.getError() << std::endl;
            abort();
        } else {
            std::cout << comp_exception.getError() << std::endl;
            return 0;
        }
    } catch (const std::exception &exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        abort();
    } catch (...) {
        std::cerr << "Error: Caught unknown exception" << std::endl;
        abort();
    }
    return 0;
}

#endif // __NODE_COMPONENTS_IMPL_H__
