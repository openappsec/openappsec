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

#ifndef __BUFFER_INTERNAL_PTR_H__
#define __BUFFER_INTERNAL_PTR_H__

template <typename T>
class Buffer::InternalPtr
{
public:
    InternalPtr(const InternalPtr &) = default;
    InternalPtr(InternalPtr &&o) : ptr(o.ptr), ref(std::move(o.ref)) { o.ptr = nullptr; }
    InternalPtr & operator=(const InternalPtr &) = default;
    InternalPtr &
    operator=(InternalPtr &&o)
    {
        ptr = o.ptr;
        ref = std::move(o.ref);
        o.ptr = nullptr;

        return *this;
    }

    operator const T *() const { return ptr; }
    const T & operator*() const { dbgAssert(ptr != nullptr) << "Accessing a moved pointer"; return *ptr; }
    const T * operator->() const { return ptr; }

private:
    friend class Buffer;

    InternalPtr(const T *_ptr, const std::shared_ptr<DataContainer> &data) : ptr(_ptr), ref(data) {}
    template<typename O>
    InternalPtr(InternalPtr<O> &&other)
            :
        ptr(reinterpret_cast<const T *>(other.ptr)),
        ref(std::move(other.ref))
    {}

    const T *ptr;
    std::shared_ptr<DataContainer> ref;
};

#endif // __BUFFER_INTERNAL_PTR_H__
