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

#ifndef _pm_adaptor_h_
#define _pm_adaptor_h_

#include <vector>
#include <iostream>

#include "general_adaptor.h"

#define KISS_PM_ALPHABET_SIZE 256
#define KISS_APPS_CPAPI

// used to copy any struct, array, string, or variable
#if 0
#define DATA_BUFF_COPY(_buf, _buf_size, _data, _data_size)    bcopy((_data), (_buf), (_data_size));    \
                                                            (_buf) += (_data_size);                    \
                                                            (*(_buf_size)) -= (_data_size)
#endif

// Not using the original DATA_BUFF_COPY which uses bcopy. On 64bit libc2.5, it seems that bcopy reads
// past the source buffer, as long as it is alligned. That's OK, but valgrind complains.
#define DATA_BUFF_COPY(_buf, _buf_size, _data, _data_size)    memcpy((_buf), (_data), (_data_size));    \
                                                            (_buf) += (_data_size);                    \
                                                            (*(_buf_size)) -= (_data_size)


#define INT_BUFF_COPY(_buf, _buf_size, _val)    do {                                                            \
                                                    int temp_val = _val;                                        \
                                                    DATA_BUFF_COPY(_buf, _buf_size, &temp_val, sizeof(int));    \
                                                } while (0)

#define U_INT_BUFF_COPY(_buf, _buf_size, _val)    do {                                                            \
                                                    u_int temp_val = _val;                                        \
                                                    DATA_BUFF_COPY(_buf, _buf_size, &temp_val, sizeof(u_int));    \
                                                } while (0)

#define U_SHORT_BUFF_COPY(_buf, _buf_size, _val)    do {                                                            \
                                                    u_short temp_val = _val;                                        \
                                                    DATA_BUFF_COPY(_buf, _buf_size, &temp_val, sizeof(u_short));    \
                                                } while (0)

#define U_CHAR_BUFF_COPY(_buf, _buf_size, _val)    do {                                                            \
                                                    u_char temp_val = _val;                                        \
                                                    DATA_BUFF_COPY(_buf, _buf_size, &temp_val, sizeof(u_char));    \
                                                } while (0)


#define DATA_BUFF_READ(_buf, _buf_size, _vbuf, _vbuf_iter, _to, _data_size)    \
do {                                        \
    if ((*(_buf_size)) >= (_data_size))     {    \
        bcopy(_buf, _to, _data_size);        \
        _buf += _data_size;                    \
        (*(_buf_size)) -= (_data_size);     \
    }                                        \
    else     {                                \
        (*(_buf_size)) = 0;                    \
    }                                        \
} while(0)

#define INT_BUFF_READ(_var, _buf, _buf_size, _vbuf, _vbuf_iter) \
    DATA_BUFF_READ(_buf, _buf_size, _vbuf, _vbuf_iter, &_var, sizeof(int))

#define U_INT_BUFF_READ(_var, _buf, _buf_size, _vbuf, _vbuf_iter) \
    DATA_BUFF_READ(_buf, _buf_size,  _vbuf, _vbuf_iter, &_var, sizeof(u_int))

#define U_SHORT_BUFF_READ(_var, _buf, _buf_size, _vbuf, _vbuf_iter) \
    DATA_BUFF_READ(_buf, _buf_size, _vbuf, _vbuf_iter, &_var, sizeof(u_short))

#define U_CHAR_BUFF_READ(_var, _buf, _buf_size, _vbuf, _vbuf_iter) \
    DATA_BUFF_READ(_buf, _buf_size, _vbuf, _vbuf_iter, &_var, sizeof(u_char))


// Serialization magics, used to verify buffer structure
#define KISS_PM_SERIALIZED            0x53525A50     // SRZP
#define KISS_DFA_SERIALIZED            0x53525A44    // SRZD
#define KISS_WM_SERIALIZED            0x53525A48     // SRZH
#define KISS_THIN_NFA_SERIALIZED    0x53525A4E       // SRZN
#define KISS_EX_REM_SERIALIZED        0x53525A58     // SRZX
#define KISS_STATS_SERIALIZED        0x53525A53      // SRZS
#define KISS_STATE_SERIALIZED        0x53525A54      // SRZT
#define KISS_PM_SERIALIZE_IGNORE_INT    0x53525A49   // SRZI
#define KISS_KW_SERIALIZED                0x53525A4B // SRZK
#define KISS_KW_MGR_SERIALIZED        0x53525A47     // SRZG


typedef enum kiss_pm_error_type_e {
    KISS_PM_ERROR_SYNTAX = 0,         // < yntax error is an error in the way the pattern is written.
    KISS_PM_ERROR_INTERNAL,           // < Internal error is an error caused by lack of resources or by design.
    KISS_PM_ERROR_COMPLEX_PATTERN,    // < Pattern is too complex to compile - too many states or too much memory
    KISS_PM_ERROR_NO_ERROR
} kiss_pm_error_type;

class KissPMError {
public:
    int pattern_id = -1;                                     //< The user's pattern id
    kiss_pm_error_type error_type = KISS_PM_ERROR_INTERNAL;  //< The error type syntax or internal
    const char *error_string = nullptr;                      //< string describing the problem
    u_int index = 0;                                         //< The place that caused the probelm. Best effort.
    const u_char *pattern_buf = nullptr;                     //< The user's pattern buffer
};

std::ostream& operator<<(std::ostream& os, const KissPMError &k);

void kiss_pm_error_set_details(KissPMError *error, kiss_pm_error_type error_type, const char error_string[]);


// PATTERNS FLAGS
// When adding a new pattern flag,
// add a metadata string below and register it in kiss_pm_pattern_flags_data in kiss_pm.c
// range from  0x00010000 to  0x80000000

// EXTERNAL PATTERN FLAGS
// These flags can be added per pattern when adding it to pm_patterns using kiss_pm_pattern_add_[simple_]pattern_...
#define KISS_PM_COMP_WM_CONT_WORD           0x80000000  // a WM continuous word -
                                                        // when used on a word we search for it without delimiters.
                                                        // Large impact on performance so think twice before using
#define KISS_PM_COMP_ALLOW_SHORT_LSS        0x40000000  // Accept short lss (shorter than kiss_pm_min_lss_sise
#define KISS_PM_COMP_LITERAL_LSS            0x20000000  // The LSS should not be normalized -
                                                        // i.e. all chars read as literals
#define KISS_PM_COMP_CASELESS               0x10000000  // Indicates a caseless pattern
#define KISS_PM_COMP_UTF8                   0x08000000  // the pattern is UTF8 encoded.
#define KISS_PM_COMP_BOUNDED_PATT           0x04000000  // find the pattern only between non word character
                                                        // (including buffer start end).
                                                        // Do not use this flag with `^` or `$`.
#define KISS_PM_COMP_DONT_USE_PCRE          0x02000000  // don't use pcre for second tier.
#define KISS_PM_COMP_VERIFY_PCRE_SYNTAX     0x01000000  // Verify that pattern that compiles with PCRE fits PM syntax

// INTERNAL PATTERN FLAGS
#define KISS_PM_COMP_FIRST_TIER_OF_PATT         0x00800000  // pattern is in it's first tier execution.
#define KISS_PM_COMP_BOUNDED_CIRCUMFLEX_ADDED   0x00400000  // This flag indicates that we have created a pattern
                                                            // for bounded word infra which is different
                                                            // from the orig patterns. In such cases we need to take
                                                            // it into considiration when we look for the match start.
#define KISS_PM_COMP_MORE_THAN_ONE_LSS          0x00200000  // The pattern is made up of one or more simple strings
#define KISS_PM_COMP_DONT_STRIP                 0x00100000  // Parse the pattern without stirping  ^/$ from the
                                                            // RE beggining/end respectively.
#define KISS_PM_LSS_AT_BUF_START                0x00080000  // LSS should be at the begining of the buffer.
#define KISS_PM_LSS_AT_BUF_END                  0x00040000  // LSS should  be at the end of the buffer.
#define KISS_PM_RE_AT_BUF_START                 0x00020000  // RE should be at the begining of the buffer.
#define KISS_PM_COMP_HAVE_SECOND_TIER           0x00010000  // the pattern needs second tier.
#define KISS_PM_COMP_NO_HISTORY                 0x00008000  // Execute this pattern only with the buffer
                                                            // (not with the history vbuf)
#define KISS_PM_COMP_REDUCE_SIZE                0x00004000  // Favor small memory consumption over good performance
// END OF PATTERNS FLAGS

// Internal flags set in the match data in kiss_dfa_insert_match_data:
#define KISS_PMGLOB_MATCH_DATA_FORCE_ADD        0x00000001  // Force add pomlob match data,
                                                            // even if the pattern has already been matched
#define KISS_PMGLOB_MATCH_OFFSET_IN_PRESENT_BUF 0x00000002  // The match offset refers to the present buffer
#define KISS_PMGLOB_REDUCE_BUFFER_LENGTH        0x00000004  // Reduce the length of tier2 buffer using
                                                            // LSS ofsets found in tier1


//How many different first tiers can a PM have? (can be smaller than the number of first tier types)
#define KISS_TIER1_MAX_NUM        2

// 8 First tier type
typedef enum kiss_tier1_type_t {
    KISS_TIER1_WM,                            // Word Matcher
    KISS_TIER1_SM,                            // DFA String matcher
    KISS_TIER1_THIN_NFA = KISS_TIER1_SM,      // Thin NFA - instead of DFA
    KISS_TIER1_NUM_TYPES,
    KISS_TIER1_INVALID = KISS_TIER1_NUM_TYPES
} kiss_tier1_type;

// which statistics the user want to see
enum kiss_pm_stats_type {
    KISS_PM_STATIC_STATS = 0,    // number of pattern, number of states, ....
    KISS_PM_DYNAMIC_STATS,       // number of executions, number of matches, avg buffer length,...
    KISS_PM_BOTH_STATS           // both statistics
};

#define K_ERROR   0x00000010
#define K_PM      0x00000400
#define K_THINNFA 0x00400000


#define KISS_PM_COMP_DIGITLESS 0x00001000 // Indicates a digitless first tier match

extern int kiss_debug_err_flag;
#define kiss_debug_err(topics, _string) if (kiss_debug_err_flag) printf _string
#define kiss_debug_wrn(topics, _string)if (kiss_debug_err_flag) printf _string
#define kiss_debug_notice(topics, _string) if (kiss_debug_err_flag) printf _string
#define kiss_debug_info(topics, _string) if (kiss_debug_err_flag) printf _string
#define kiss_debug(topics) if (kiss_debug_err_flag) printf
#define kiss_debug_info_perf(topics, _string)

#define kiss_dbg(topics) if (kiss_debug_err_flag)

#define kiss_vbuf void *
#define kiss_vbuf_iter void *


// Which character translations are needed?
enum kiss_pmglob_char_xlation_flags_e {
    KISS_PMGLOB_CHAR_XLATION_NONE     = 0x00,
    KISS_PMGLOB_CHAR_XLATION_CASE     = 0x01,
    KISS_PMGLOB_CHAR_XLATION_DIGITS   = 0x02,
};

enum kiss_pm_dump_format_e {
    KISS_PM_DUMP_XML,           // XML, for opening with JFlap
    KISS_PM_DUMP_CSV,           // CSV, for opening with Excel
    KISS_PM_DUMP_WIKI           // WIKI, for copy&paste into Wiki (Confluence)
};


void kiss_pmglob_char_xlation_build(enum kiss_pmglob_char_xlation_flags_e flags, u_char tab[KISS_PM_ALPHABET_SIZE]);
void kiss_pmglob_char_xlation_build_reverse(
    const u_char tab[KISS_PM_ALPHABET_SIZE],
    u_char rev[KISS_PM_ALPHABET_SIZE]
);

void kiss_debug_start();
void kiss_debug_stop();

#endif // _pm_adaptor_h_
