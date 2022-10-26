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

#ifndef __BUFFER_DATA_CONTAINER_H__
#define __BUFFER_DATA_CONTAINER_H__

class Buffer::DataContainer
{
public:
    DataContainer() : ptr(nullptr), len(0) {}
    DataContainer(std::vector<u_char> &&_vec);
    DataContainer(const u_char *_ptr, uint _len, MemoryType _type);
    DataContainer(const DataContainer &) = delete;
    DataContainer(DataContainer &&) = delete;
    const u_char * data() const { return ptr; }
    uint size() const { return len; }

    // The "checkOnwership" method returns the place where the current memory type is owned by the I/S.
    // This makes it possible to check if the memory has been moved (from VOLATILE to ONWED).
    bool * checkOnwership() { return &is_owned; }

    void
    takeOwnership()
    {
        vec = std::vector<u_char>(ptr, ptr + len);
        ptr = vec.data();
        is_owned = true;
    }

    template<class Archive>
    void
    save(Archive &ar, uint32_t) const
    {
        if (is_owned) {
            ar(vec);
        } else {
            std::vector<u_char> data(ptr, ptr + len);
            ar(data);
        }
    }

    template<class Archive>
    void
    load(Archive &ar, uint32_t)
    {
        ar(vec);
        is_owned = true;
        ptr = vec.data();
        len = vec.size();
    }

private:
    // If the memory is OWNED (not STATIC or VOLATILE), the "vec" member is holding it - otherwise it is empty.
    std::vector<u_char> vec;
    // The "ptr" member points to the the beginning of the data, regardless of the type of memory.
    const u_char *ptr = nullptr;
    uint len = 0;
    bool is_owned = true;
};

#endif // __BUFFER_DATA_CONTAINER_H__
