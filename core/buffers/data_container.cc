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

#include "buffer.h"

Buffer::DataContainer::DataContainer(std::vector<u_char> &&_vec)
        :
    vec(std::move(_vec)),
    ptr(vec.data()),
    len(vec.size())
{
}

Buffer::DataContainer::DataContainer(const u_char *_ptr, uint _len, MemoryType _type)
        :
    len(_len)
{
    if (_type == MemoryType::OWNED) {
        vec = std::vector<u_char>(_ptr, _ptr + len);
        ptr = vec.data();
    } else {
        ptr = _ptr;
        is_owned = false;
    }
}
