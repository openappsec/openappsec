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

#ifndef __BUFFER_HELPER_FUNCTIONS_H__
#define __BUFFER_HELPER_FUNCTIONS_H__

// Function to allow comparison with types that have data (of types char or u_char) and size
template <typename T>
bool
operator==(const Buffer &buf, const T &t)
{
    return buf.isEqual(t.data(), t.size());
}

template <typename T>
bool
operator==(const T &t, const Buffer &buf)
{
    return buf.isEqual(t.data(), t.size());
}

template <typename T>
bool
operator!=(const Buffer &buf, const T &t)
{
    return !buf.isEqual(t.data(), t.size());
}

template <typename T>
bool
operator!=(const T &t, const Buffer &buf)
{
    return !buf.isEqual(t.data(), t.size());
}

#endif // __BUFFER_HELPER_FUNCTIONS_H__
