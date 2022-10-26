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

#ifndef __CONTEXT_H__
#error "param.h should not be included directly"
#endif // __CONTEXT_H__

namespace EnvKeyAttr
{

class ParamAttr
{
public:
    ParamAttr() {}

    template <typename ... Attr>
    ParamAttr(Attr ... attr)
    {
        setAttr(attr...);
    }

    bool doesMatch(const ParamAttr &param) const;

private:
    template <typename Attr, typename ... MoreAttr>
    void
    setAttr(Attr attr, MoreAttr ... more_attr)
    {
        setAttr(attr);
        setAttr(more_attr...);
    }

    void setAttr(const LogSection &section) { log_section = section; }
    void setAttr(const Verbosity &level) { verbosity_level = level; }

    LogSection log_section = LogSection::NONE;
    Verbosity verbosity_level = Verbosity::NONE;
};

} // EnvKeyAttr
