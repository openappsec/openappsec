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

#ifndef __BUFFER_SEGMENT_H__
#define __BUFFER_SEGMENT_H__

class Buffer::Segment
{
public:
    Segment() {}
    Segment(std::vector<u_char> &&_vec);
    Segment(const u_char *_ptr, uint _len, MemoryType _type);
    ~Segment();
    Segment(const Segment &);
    Segment(Segment &&);
    Segment & operator=(const Segment &);
    Segment & operator=(Segment &&);

    const u_char * data() const;
    uint size() const { return len; }

    template<class Archive>
    void
    save(Archive &ar, uint32_t) const
    {
        ar(data_container, offset, len);
    }

    template<class Archive>
    void
    load(Archive &ar, uint32_t)
    {
        // In the usual case, the `load` method is called on a newly default constructed object.
        // However, since there is no guarantee that will always be the case, we need to make sure to handle the case
        // where the object the data is loaded to is currently used as a PRIMARY.
        if (type==Volatility::PRIMARY && !data_container.unique()) {
            data_container->takeOwnership();
        }

        ar(data_container, offset, len);

        type = Volatility::NONE;
        is_owned = nullptr;
        ptr = data_container->data() + offset;
    }

private:
    friend class Buffer;

    // The "data_container" is the smart pointer to the actual memory.
    std::shared_ptr<DataContainer> data_container;
    // The "offset" and "len" members are used to indicate what part of the shared memory the segment refers to.
    uint offset = 0, len = 0;

    // The "type" member holds the volatility status of the memory.
    Volatility type = Volatility::NONE;
    // The "is_owned" member is used in case of SECONDARY volatility to check if ownership of the memory was taken.
    // It a pointer to `data_container->is_owned` if the segement is SECONDARY, and nullptr if it isn't.
    bool *is_owned = nullptr;
    // The "ptr" member is used to gain access to the memory directly without going to through the shared memory
    // pointer (fast path).
    const u_char *ptr = nullptr;
};

#endif // __BUFFER_SEGMENT_H__
