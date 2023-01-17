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

#include "kiss_patterns.h"
#include <vector>
#include <ctype.h>
#include "general_adaptor.h"
#include "pm_adaptor.h"

// Add a character's printable representation to a buffer.
// Returns the number of bytes written.
static u_int
pm_str_one_char_to_debug_buf(u_char *buf, int len, u_char ch, BOOL for_csv)
{
    char single_char_buf[10];
    int single_char_len;

    // Get a printable representation of the character
    if (isprint(ch) && !(ch == '"' && for_csv)) {
        single_char_buf[0] = ch;
        single_char_len = 1;
    } else {
        snprintf(single_char_buf, sizeof(single_char_buf), "\\x%02x", ch);
        single_char_buf[sizeof(single_char_buf)-1] = '\0';
        single_char_len = strlen(single_char_buf);
    }

    if (single_char_len > len) {
        // See that we don't exceed the buffer, and leave room for \0.
        single_char_len = len;
    }

    bcopy(single_char_buf, buf, single_char_len);
    return single_char_len;
}

// Debug only - Returns a printable character pointer for the non null-terminated string
static const u_char *
pm_str_to_debug_charp_ex(const u_char *str, u_int size, BOOL for_csv)
{
    static u_char buf[200];
    u_int i;
    u_char *buf_p;

    // Copy the string. But replace unprintable characters (most importantly \0) with underscores.
    buf_p = &buf[0];
    for (i=0; i<size; i++) {
        int remaining_len = buf+sizeof(buf)-buf_p;
        if (remaining_len <= 1) break;
        buf_p += pm_str_one_char_to_debug_buf(buf_p, remaining_len-1, str[i], for_csv);
    }
    *buf_p = '\0';
    return buf;
}

static const u_char *
pm_str_to_debug_charp(const u_char *str, u_int size)
{
    return pm_str_to_debug_charp_ex(str, size, FALSE);
}


// *********************** STRING *******************************

kiss_pmglob_string_s::kiss_pmglob_string_s(const char *buffer, size_t size, int _pattern_id, u_int _flags)
        :
    kiss_pmglob_string_s(reinterpret_cast<const u_char *>(buffer), size, _pattern_id, _flags)
{
}

kiss_pmglob_string_s::kiss_pmglob_string_s(const u_char *buffer, size_t size, int _pattern_id, u_int _flags)
{
    dbgAssert(buffer && size > 0) << "Illegal arguments";
    buf.resize(size);
    memcpy(buf.data(), buffer, size);
    pattern_id = _pattern_id;
    flags = _flags;
    return;
}


// Returns the pattern of the pattern as u_char*
int
kiss_pmglob_string_get_id(const kiss_pmglob_string_s *pm_string)
{
    KISS_ASSERT(pm_string != nullptr, "Illegal arguments");
    return pm_string->pattern_id;
}


// Returns the size of the pattern
u_int
kiss_pmglob_string_get_size(const kiss_pmglob_string_s * pm_string)
{
    KISS_ASSERT(pm_string != nullptr, "Illegal arguments");
    return pm_string->buf.size();
}

// Returns the pattern of the pattern as u_char*
const u_char *
kiss_pmglob_string_get_pattern(const kiss_pmglob_string_s *pm_string)
{
    KISS_ASSERT(pm_string != nullptr, "Illegal arguments");
    return pm_string->buf.data();
}


// Debug only - Returns a printable character pointer for the string
const u_char *
kiss_pmglob_string_to_debug_charp(const kiss_pmglob_string_s *pm_string)
{
    return pm_str_to_debug_charp(kiss_pmglob_string_get_pattern(pm_string), kiss_pmglob_string_get_size(pm_string));
}


u_int
kiss_pmglob_string_get_flags(const kiss_pmglob_string_s *pm_string)
{
    KISS_ASSERT(pm_string != nullptr, "Illegal arguments");
    return pm_string->flags;
}
