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

#ifndef __h_kiss_thin_nfa_impl_h__
#define __h_kiss_thin_nfa_impl_h__

// *********************** OVERVIEW ******************************
// Thin NFA definitions, which are only used by Thin NFA files.
// 1. A list of patterns which is associated with a finite state.
// 2. APIs for building and destroying the Thin NFA structures.
// ****************************************************************

#include <list>
#include <vector>
#include <memory>

#include "i_pm_scan.h"
#include "kiss_patterns.h"
#include "kiss_pm_stats.h"
#include "kiss_thin_nfa_base.h"

KISS_ASSERT_COMPILE_TIME(KISS_PM_ALPHABET_SIZE == KISS_THIN_NFA_ALPHABET_SIZE);

// Information we keep about a pattern
typedef struct {
    int id;                         // PM Internal pattern ID
    u_int pattern_id_flags;         // KISS_PM_COMP_ prefix
    u_int len;
} kiss_thin_nfa_pattern_t;

// Linked list of pattern information - held per finite state, to indicate what it's accepting.
typedef struct kiss_thin_nfa_pattern_list_s {
    struct kiss_thin_nfa_pattern_list_s *next;
    kiss_thin_nfa_pattern_t pattern;
} kiss_thin_nfa_pattern_list_t;

// Array of pattern information - offset to it held per finite state, to indicate what it's accepting.
typedef struct kiss_thin_nfa_pattern_array_s {
    u_int n_patterns;
    // NOTE! Always keep this last!
    kiss_thin_nfa_pattern_t pattern[1]; // Dynamic array, not really 1
    // Do NOT add anything here!
} kiss_thin_nfa_pattern_array_t;

static CP_INLINE u_int
kiss_thin_nfa_pattern_array_size(const u_int n_patterns)
{
    // assignement of NULL value so Windows compiler won't cry about unused variable.
    kiss_thin_nfa_pattern_array_t CP_MAYBE_UNUSED *dummy = NULL;

    // We substract sizeof(->pattern), becuase it's already included in the sizeof
    // of the whole struct.
    return (sizeof(*dummy) + n_patterns * sizeof(dummy->pattern[0]) - sizeof(dummy->pattern));;
}

// ThinNFA statistics

// Specific ThinNFA Statistics
struct kiss_thin_nfa_specific_stats_s {
    u_int num_of_states;            // number of states in this thin_nfa
    u_int num_of_final_states;      // number of final states in this thin_nfa
};

// Statistics for ThinNFA
struct kiss_thin_nfa_stats_s {
    struct kiss_pm_stats_common_s common;              // Run-time (per-CPU, dynamic) and build-time common statistics
    struct kiss_thin_nfa_specific_stats_s specific;    // Build-time specific ThinNFA statistics
};
typedef struct kiss_thin_nfa_stats_s *kiss_thin_nfa_stats;

// Compressed BNFA offset -> state depth map
struct kiss_thin_nfa_depth_map_s {
    u_char *mem_start;          // Array of depth per BNFA compressed offset
    u_int size;
    u_char *offset0;            // Positive/negative offsets are relative to this
};

#define KISS_THIN_NFA_MAX_ENCODABLE_DEPTH 255        // Fit in u_char

// A Compiled Thin NFA, used at runtime
class KissThinNFA {
public:
    ~KissThinNFA();

    kiss_bnfa_state_t *bnfa_start;                  // The first (in memory) and initial state
    kiss_bnfa_state_t *bnfa;                        // The state at offset 0 (somewhere in the middle)
    kiss_bnfa_offset_t min_bnfa_offset;             // The offset of the first (and initial) state.
    kiss_bnfa_offset_t max_bnfa_offset;             // The offset after the last state.
    enum kiss_thin_nfa_flags_e flags;
    u_int match_state_num;                          // Number of match states in the machine
    u_int pattern_arrays_size;                      // Total size in bytes of concatanated pattern arrays
    kiss_thin_nfa_pattern_array_t *pattern_arrays;  // A pointer to a buffer holding ALL pattern arrays, for ALL states
    struct kiss_thin_nfa_stats_s stats;
    u_int max_pat_len;                              // Length of the longest string
    u_char xlation_tab[KISS_PM_ALPHABET_SIZE];      // For caseless/digitless
    struct kiss_thin_nfa_depth_map_s depth_map;     // State -> Depth mapping
};

static CP_INLINE u_int
kiss_thin_nfa_pat_array_ptr_to_offset(const KissThinNFA *nfa, const kiss_thin_nfa_pattern_array_t *pat_arr)
{
    return (const char *)pat_arr - (const char *)(nfa->pattern_arrays);
}

static CP_INLINE kiss_thin_nfa_pattern_array_t *
kiss_thin_nfa_offset_to_pat_array_ptr(const KissThinNFA *nfa, const u_int offset)
{
    return (kiss_thin_nfa_pattern_array_t *)((char *)(nfa->pattern_arrays) + offset);
}

// Get a state's depth
// For very deep states (offset >= 255), returns the maximum pattern length,
//  which would be greater/equal the real state depth.
static CP_INLINE u_int
kiss_bnfa_offset_to_depth(const KissThinNFA *nfa, kiss_bnfa_comp_offset_t comp_offset)
{
    u_int depth = nfa->depth_map.offset0[comp_offset];
    return (depth==KISS_THIN_NFA_MAX_ENCODABLE_DEPTH) ? nfa->max_pat_len : depth;
}


// Create a new empty Thin NFA.
// Allocates the BNFA and the match_data array, but doesn't fill them.
std::unique_ptr<KissThinNFA>
kiss_thin_nfa_create(
    u_int match_state_num,
    kiss_bnfa_offset_t min_offset,
    kiss_bnfa_offset_t max_offset
);


// Add a pattern (with given id, flags and length) to a list.
// pat_list should point to the head of the list, *pat_list may be modified.
kiss_ret_val
kiss_thin_nfa_add_pattern_id(
    kiss_thin_nfa_pattern_list_t **pat_list,
    const kiss_thin_nfa_pattern_t *pat_info
);

// Free all patterns on a list.
void kiss_thin_nfa_free_pattern_ids(kiss_thin_nfa_pattern_list_t *pat_list);

// Compile a Thin NFA
std::unique_ptr<KissThinNFA>
kiss_thin_nfa_compile(
    const std::list<kiss_pmglob_string_s> &patterns,
    u_int compile_flags,
    KissPMError *error
);


// Validate Thin NFA
BOOL kiss_thin_nfa_is_valid(const KissThinNFA *nfa_h);

void
kiss_thin_nfa_exec(KissThinNFA *nfa_h, const Buffer &buffer, std::vector<std::pair<uint, uint>> &matches);

// Dump a PM
kiss_ret_val kiss_thin_nfa_dump(const KissThinNFA *nfa_h, enum kiss_pm_dump_format_e format);

// Debugging macro wrappers.
// All get a format string plus parameters in double parenthesis:
//  thinnfa_debug(("%s: hello, world\n", rname));
// Meaning of each macro:
// thinnfa_debug_critical     - Critical error, printed by default.
// thinnfa_debug_err         - Error we should live with (e.g. usage error, memory allocation), not printed by default.
// thinnfa_debug            - Normal debug messages.
// thinnfa_debug_major        - Debug messages about several major events in Thin NFA constuction. Use sparingly.
// thinnfa_debug_extended    - Low level debug messages, which may be printed in large numbers.
// thinnfa_dbg                - An "if" statement checking the debug flag (equivalent to thinnfa_debug).
#define thinnfa_debug_critical(_str)    kiss_debug_err(K_ERROR, _str)
#define thinnfa_debug_err(_str)            kiss_debug_err(K_THINNFA|K_PM, _str)
#define thinnfa_debug(_str)             kiss_debug_info(K_THINNFA, _str)
#define thinnfa_debug_major(_str)         kiss_debug_info(K_THINNFA|K_PM, _str)
#define thinnfa_debug_extended(_str)     kiss_debug_info(K_THINNFA, _str)
#define thinnfa_debug_perf(_str)        kiss_debug_info_perf(K_THINNFA, _str)
#define thinnfa_dbg()                    kiss_dbg(K_THINNFA)

#endif // __h_kiss_thin_nfa_impl_h__
