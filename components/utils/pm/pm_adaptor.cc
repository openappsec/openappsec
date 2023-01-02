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

#include "pm_adaptor.h"

int kiss_debug_err_flag = 0;

void
kiss_debug_start()
{
    kiss_debug_err_flag = 1;
}

void
kiss_debug_stop()
{
    kiss_debug_err_flag = 0;
}


void
kiss_pmglob_char_xlation_build(enum kiss_pmglob_char_xlation_flags_e flags, u_char tab[KISS_PM_ALPHABET_SIZE])
{
    u_int i;

    // Find the canonic character for each character.
    for (i=0; i<KISS_PM_ALPHABET_SIZE; i++) {
        u_char ch = (u_char)i;
        if ((flags & KISS_PMGLOB_CHAR_XLATION_DIGITS) && isdigit(ch)) {
            tab[ch] = '0';
        } else if (flags & KISS_PMGLOB_CHAR_XLATION_CASE) {
            tab[ch] = tolower(ch);
        } else {
            tab[ch] = ch;
        }
    }
}


// Reverse a character translation table, so we can all charaters that map to a canonic character.
//
// Since the reverse map maps one character to many, it's implemented this way:
// 1. Characters are arranged in groups - all characters in a group map to the same canonic character.
// 2. A group is represented as a cyclic linked list, where each character points to the next in the same group.
// 3. Instead of pointers, we use characters - for each character, rev[ch] is the next character in the group.
void
kiss_pmglob_char_xlation_build_reverse(const u_char tab[KISS_PM_ALPHABET_SIZE], u_char rev[KISS_PM_ALPHABET_SIZE])
{
    u_int i;

    // Put each character in its own group
    for (i=0; i<KISS_PM_ALPHABET_SIZE; i++) {
        u_char ch = (u_char)i;
        rev[ch] = ch;
    }

    // Take each character which is not canonic, and add it to its canonic char's group.
    for (i=0; i<KISS_PM_ALPHABET_SIZE; i++) {
        u_char ch = (u_char)i;
        u_char canonic = tab[ch];

        if (canonic == ch) {
            // Already in the correct group (its own group)
            continue;
        }
        // Add to the linked list
        rev[ch] = rev[canonic];
        rev[canonic] = ch;
    }
}

std::ostream&
operator<<(std::ostream& os, const KissPMError &e)
{
    return os << "Reason: " << e.error_string;
}


void
kiss_pm_error_set_details(KissPMError *error,
                                kiss_pm_error_type error_type,
                                const char error_string[])
{
    if ((error == NULL) || (error->error_string != NULL)) // No error struct or error already set. Not a problem
        return;

    error->error_type = error_type;
    error->error_string = error_string;
    return;
}
