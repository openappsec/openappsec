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

#ifndef __kiss_patterns_h__
#define __kiss_patterns_h__

#include <vector>
#include <list>
#include "pm_adaptor.h"

// kiss_pmglob_string functions

class kiss_pmglob_string_s {
    public:
        explicit kiss_pmglob_string_s(const   char *buffer, size_t size, int _pattern_id, u_int _flags);
        explicit kiss_pmglob_string_s(const u_char *buffer, size_t size, int _pattern_id, u_int _flags);

        std::vector<u_char> buf;
        int pattern_id;
        u_int flags;
};


// Returns the size of pattern
//
// Parameters:
//    pattern - the pattern.
// Return value:
//    int - the size that this pattern represents.
KISS_APPS_CPAPI
u_int kiss_pmglob_string_get_size(const kiss_pmglob_string_s *pattern);

// Returns the pattern of the pattern as u_char*
//
// Parameters:
//    patterns - the pattern.
// Return value:
//    u_char * - the pattern that this pattern represents.
KISS_APPS_CPAPI
const u_char *kiss_pmglob_string_get_pattern(const kiss_pmglob_string_s *pattern);

// For debugging only - returns a printable pointer for the string.
// Replaces unprintable characters with underscores.
//
// Note: In multithreaded situations, the buffer returned may be overrun by another thread.
//  At worst, this would lead to an incorrect string being printed.
KISS_APPS_CPAPI
const u_char *kiss_pmglob_string_to_debug_charp(const kiss_pmglob_string_s *pm_string);

// Returns the id of pattern
//
// Parameters:
//    patterns - the pattern.
// Return value:
//    id - the pattern_id that this pattern represents.
KISS_APPS_CPAPI
int kiss_pmglob_string_get_id(const kiss_pmglob_string_s *pattern);


KISS_APPS_CPAPI
u_int kiss_pmglob_string_get_flags(const kiss_pmglob_string_s *pattern);


#endif // __kiss_patterns_h__
