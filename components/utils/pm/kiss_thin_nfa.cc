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

// Thin NFA I/S
// ------------
// The thin NFA allows building and executing an automaton for string search, using the
//  Aho-Corasick algorithm.
// The resulting automaton is built in a compact representation. Some states are "full" - they
//  have an explicit transition per character. Others are "partial" - they have some explicit transitions,
//  plus a "default transition". This is an epsilon-transition. For characters which don't have an
//  explicit transition, we follow the default transition, and look up the same character there.
//
// Source files
// ------------
// kiss_thin_nfa.c (this file) - execution code.
// kiss_thin_nfa_build.c - allocation and destruction code. Contains code which is common to compilation
//  and serialization/deserialization. All objects which are part of the comipled automaton are created here.
// kiss_thin_nfa_compile.c - compilation code. Contains the logic that converts a set of strings into an automaton.
// kiss_thin_nfa_analyze.c - Validation and dump. Code that reads the BNFA and tries to make sense of it.
// kiss_thin_nfa_impl.h - internal header file. APIs and definitions between the different source files.


// ********************* INCLUDES **************************
#include "kiss_thin_nfa_impl.h"

// Internal execution flags passed to kiss_dfa_exec_one_buf:
#define KISS_PM_EXEC_LAST_BUFF 0x00000001    // This is the last buffer (preset buffer or the last buffer in vbuf)


// The runtime status of the Thin NFA
struct kiss_bnfa_runtime_s {
    KissThinNFA *nfa_h;                              // The NFA we're executing
    kiss_bnfa_comp_offset_t last_bnfa_offset;        // Last state reached by exec_one_buf
    std::vector<std::pair<uint, uint>> *matches;     // The matches we've found so far
    u_int scanned_so_far;                            // The length of all buffers before the current buffer
};


// Critical code path debugging - enabled only in debug mode.
#define THIN_NFA_TRACE_TRANS(runtime, next_off, ch, op) \
    thinnfa_debug_perf(                                 \
        "%s: Transition by 0x%02x to %d - %s\n",        \
        FILE_LINE,                                      \
        ch,                                             \
        kiss_bnfa_offset_decompress(next_off),          \
        op                                              \
    )

#define TRANSLATE_CHAR_IF_NEEED(do_char_trans, char_trans_table, ch)    \
    ((u_char)((do_char_trans) ? ((char_trans_table)[ch]) : (ch)))

// Given a match for a pattern at a given position, insert an entry to the match list.
// We may add more than one entry, depending on the number of matching patterns.
//
// Parameters:
//  runtime - the current status of Thin NFA execution.
//  one_buf_offset - the offset of the match, within the buffer currently scanned.
//     Together with runtime->scanned_so_far we can get the real match offset.
//  one_buf_len - the length of the buffer currently scanned. Used for $ processing.
//  exec_flags - the flags used.
static CP_INLINE void
kiss_thin_nfa_handle_match(struct kiss_bnfa_runtime_s *runtime, u_int pat_arr_offset,
    u_int one_buf_offset, u_int one_buf_len, u_int exec_flags)
{
    static const char rname[] = "kiss_thin_nfa_handle_match";
    u_int match_pos;
    const kiss_thin_nfa_pattern_array_t *pat_arr;
    const kiss_thin_nfa_pattern_t *curr_id;
    const kiss_thin_nfa_pattern_t *pat_end;

    // Where was the match? one_buf_offset is already moved beyond the characeter that caused the match,
    // so we subtract one to get this character's offset.
    match_pos = runtime->scanned_so_far + (one_buf_offset - 1);
    pat_arr = kiss_thin_nfa_offset_to_pat_array_ptr(runtime->nfa_h, pat_arr_offset);
    // Go over the patterns and add them to the match queue.
    pat_end = &(pat_arr->pattern[pat_arr->n_patterns]);
    thinnfa_debug_perf((
        "%s: Going over %u patterns, starting from offset %u\n",
        rname,
        pat_arr->n_patterns,
        pat_arr_offset
    ));
    for (curr_id = &(pat_arr->pattern[0]); curr_id != pat_end; curr_id++) {
        thinnfa_debug(("%s: Match for pattern ID %d at %d len %d\n", rname, curr_id->id, match_pos, curr_id->len));

        // Handle ^ - An N byte pattern at the start of the buffer would match at byte N-1.
        // NOTE: If the anchored state optimization is implemented in compilation, this test isn't needed.
        if ((curr_id->pattern_id_flags & KISS_PM_LSS_AT_BUF_START) && (match_pos != curr_id->len - 1)) {
            thinnfa_debug_perf(("%s: Not match because of ^ %d\n", rname, curr_id->id));
            continue;
        }

        // Handle $ - We must match at the buffer end, and it must be the last buffer
        if ((curr_id->pattern_id_flags & KISS_PM_LSS_AT_BUF_END) &&
                !((one_buf_offset == one_buf_len) && (exec_flags & KISS_PM_EXEC_LAST_BUFF))) {
            thinnfa_debug_perf(("%s: Not match because of $ %d\n", rname, curr_id->id));
            continue;
        }
        runtime->matches->emplace_back(curr_id->id, match_pos);
    }

    return;
}


// Wrapper to kiss_thin_nfa_handle_match, gets the state offset, not the ID.
static CP_INLINE void
kiss_thin_nfa_handle_match_state(struct kiss_bnfa_runtime_s *runtime, kiss_bnfa_comp_offset_t cur_offset,
    u_int one_buf_offset, u_int one_buf_len, u_int exec_flags)
{
    const kiss_bnfa_state_t *state = kiss_bnfa_comp_offset_to_state(
        runtime->nfa_h->bnfa,
        cur_offset,
        KISS_BNFA_STATE_MATCH
    );
    kiss_thin_nfa_handle_match(runtime, state->match.match_id, one_buf_offset, one_buf_len, exec_flags);
}

// Calculate the next state's offset, given a state and character. Good for full states only.
// Faster than kiss_thin_nfa_get_next_offset. An offset peremeter is compressed 16-bit offset
//  The returned offset is also compressed
static CP_INLINE kiss_bnfa_comp_offset_t
kiss_thin_nfa_get_next_offset_full(const kiss_bnfa_state_t *bnfa, kiss_bnfa_comp_offset_t offset,
    unsigned char char_to_find)
{
    const kiss_bnfa_state_t *state = kiss_bnfa_comp_offset_to_state(bnfa, offset, KISS_BNFA_STATE_FULL);
    return (kiss_bnfa_comp_offset_t)state->full.transitions[char_to_find];
}


// Calculate the next state's offset, given a state and character. Good for partial states only.
// Also indicates whether the buffer position should be incremented (i.e. if an explicit transition was found)
static CP_INLINE kiss_bnfa_comp_offset_t
kiss_thin_nfa_get_next_offset_partial(const kiss_bnfa_state_t *bnfa, kiss_bnfa_comp_offset_t offset,
    unsigned char char_to_find, BOOL *inc_pos)
{
    const kiss_bnfa_state_t *state = kiss_bnfa_comp_offset_to_state(bnfa, offset, KISS_BNFA_STATE_PARTIAL);
    u_int trans_num = state->partial.trans_num;
    u_int i;

    // Simple linear search is fast for a few transitions. If we have many, we use a full state anyway.
    for (i = 0; i < trans_num; i++) {
        const struct kiss_bnfa_partial_transition_s *tran = &state->partial.transitions[i];
        // Smaller? Keep looking. Larger? Give up (transitions are sorted).
        if (tran->tran_char < char_to_find) continue;
        if (tran->tran_char > char_to_find) break;

        // Found the character (explicit transition) - consume a characeter and move the automaton
        *inc_pos = TRUE;
        return tran->next_state_offset;
    }

    // No explicit transition found - move to the fail state, without consuming a character.
    *inc_pos = FALSE;
    return state->partial.fail_state_offset;
}


//  Calculate the next state's offset, when the current is a match state.
//  Doesn't consume a character (epsilon transition)
static CP_INLINE kiss_bnfa_comp_offset_t
kiss_thin_nfa_get_next_offset_match(CP_MAYBE_UNUSED const kiss_bnfa_state_t *bnfa, kiss_bnfa_comp_offset_t offset)
{
    // After a match state we just move to the next consecutive state.
    return offset + (sizeof(kiss_bnfa_match_state_t) / KISS_BNFA_STATE_ALIGNMENT);
}

#define PARALLEL_SCANS_NUM 4        // 4 heads scanning the buffer
#define UNROLL_FACTOR 4                // Advance each head 4 bytes per loop


// Move one head of the state machine. bnfa_offset must not be a match state.
static CP_INLINE kiss_bnfa_comp_offset_t
parallel_scan_advance_one(const kiss_bnfa_state_t *bnfa, kiss_bnfa_comp_offset_t bnfa_offset, const unsigned char ch)
{
    while (bnfa_offset >= 0) {
        BOOL inc_pos;
        // Partial state - Look for an explicit transition, or use the fail state
        bnfa_offset = kiss_thin_nfa_get_next_offset_partial(bnfa, bnfa_offset, ch, &inc_pos);
        if (inc_pos) {
            // Found an explicit transition - can move to the next state.
            return bnfa_offset;
        }
    }

    // Full state (either we started with full, or the fail state chain reached one)
    return kiss_thin_nfa_get_next_offset_full(bnfa, bnfa_offset, ch);
}


//  Check if all heads are on a full state.
//  If they are - advance all heads and return TRUE.
//  If they aren't - do nothing and return FALSE.
static CP_INLINE BOOL
parallel_scan_advance_if_full(
    const kiss_bnfa_state_t *bnfa,
    kiss_bnfa_comp_offset_t *bnfa_offsets,
    const unsigned char **buf_pos
)
{
    kiss_bnfa_comp_offset_t offsets_and;

    // If the bitwise AND of 4 offsets (PARALLEL_SCANS_NUM) is negative, they're all negaitve, so all states are full.
    offsets_and = bnfa_offsets[0] & bnfa_offsets[1] & bnfa_offsets[2] & bnfa_offsets[3];
    if (CP_UNLIKELY(offsets_and >= 0)) return FALSE;

    // All states are full - make 4 transitions (PARALLEL_SCANS_NUM).
    bnfa_offsets[0] = kiss_thin_nfa_get_next_offset_full(bnfa, bnfa_offsets[0], *(buf_pos[0]));
    buf_pos[0]++;
    bnfa_offsets[1] = kiss_thin_nfa_get_next_offset_full(bnfa, bnfa_offsets[1], *(buf_pos[1]));
    buf_pos[1]++;
    bnfa_offsets[2] = kiss_thin_nfa_get_next_offset_full(bnfa, bnfa_offsets[2], *(buf_pos[2]));
    buf_pos[2]++;
    bnfa_offsets[3] = kiss_thin_nfa_get_next_offset_full(bnfa, bnfa_offsets[3], *(buf_pos[3]));
    buf_pos[3]++;

    return TRUE;
}


//  Repeat parallel_scan_advance_if_full up to 4 times (UNROLL_FACTOR).
//  Retrurn TRUE if all 4 were done, FALSE if stopped earlier.
static CP_INLINE BOOL
parallel_scan_advance_if_full_unroll(
    const kiss_bnfa_state_t *bnfa,
    kiss_bnfa_comp_offset_t *bnfa_offsets,
    const unsigned char **buf_pos
)
{
    if (!parallel_scan_advance_if_full(bnfa, bnfa_offsets, buf_pos)) return FALSE;
    if (!parallel_scan_advance_if_full(bnfa, bnfa_offsets, buf_pos)) return FALSE;
    if (!parallel_scan_advance_if_full(bnfa, bnfa_offsets, buf_pos)) return FALSE;
    if (!parallel_scan_advance_if_full(bnfa, bnfa_offsets, buf_pos)) return FALSE;
    return TRUE;
}


// Find the offset where each head should start and stop
static void
calc_head_buf_range(const u_char *buffer, u_int len, const u_char **head_start_pos, const u_char **head_end_pos)
{
    static const char rname[] = "calc_head_buf_range";
    const u_char *orig_buf = buffer;
    u_int len_per_head = len / PARALLEL_SCANS_NUM;
    u_int rem = len % PARALLEL_SCANS_NUM;
    u_int i;

    for (i=0; i<PARALLEL_SCANS_NUM; i++) {
        u_int head_len = len_per_head;
        // Give each head its share, late heads get a part of the remainder.
        //  The "Handle remainders" loop below assumes the last head has the largest part.
        if (i >= PARALLEL_SCANS_NUM-rem) head_len++;
        head_start_pos[i] = buffer;
        buffer += head_len;
        head_end_pos[i] = buffer;
        thinnfa_debug(("%s: Head %u gets range %ld:%ld\n", rname,
            i, head_start_pos[i]-orig_buf, head_end_pos[i]-orig_buf));
    }
}

// Set the initial BNFA offset for each head
static void
set_head_bnfa_offset(
    struct kiss_bnfa_runtime_s *runtime,
    kiss_bnfa_comp_offset_t *bnfa_pos,
    const u_char **buf_pos,
    const u_char *buffer
)
{
    const KissThinNFA *nfa_h = runtime->nfa_h;
    kiss_bnfa_comp_offset_t init_off = kiss_bnfa_offset_compress(nfa_h->min_bnfa_offset);
    u_int i;

    if (nfa_h->flags & KISS_THIN_NFA_HAS_ANCHOR) {
        // Start from the root (next full state after the anchored root)
        init_off++;
    }

    // Heads that scan from the beginning of the buffer, will start at previous buffer's ending state.
    // The rest start anew.
    // Several scanning heads will start at buffer's beginning when buffer's size is less than PARALLEL_SCANS_NUM
    for (i=0; i<PARALLEL_SCANS_NUM; i++) {
        if (buf_pos[i] - buffer == 0) {
            bnfa_pos[i] = runtime->last_bnfa_offset;
        } else {
            bnfa_pos[i] = init_off;
        }
    }
}


// Run Thin NFA parallely on a single buffer.
static CP_INLINE void
kiss_thin_nfa_exec_one_buf_parallel_ex(
    struct kiss_bnfa_runtime_s *runtime,
    const u_char *buffer,
    u_int len, u_int flags,
    BOOL do_char_trans,
    u_char *char_trans_table
)
{
    const kiss_bnfa_state_t *bnfa = runtime->nfa_h->bnfa;
    const unsigned char *end, *buf_pos[PARALLEL_SCANS_NUM], *head_end_pos[PARALLEL_SCANS_NUM];
    kiss_bnfa_comp_offset_t bnfa_offset[PARALLEL_SCANS_NUM];
    u_int i;
    u_int overlap_bytes;
    int overlap_head_mask;

    // set starting position, ending position and state for each scanning head
    calc_head_buf_range(buffer, len, buf_pos, head_end_pos);
    set_head_bnfa_offset(runtime, bnfa_offset, buf_pos, buffer);

    end = buffer + len;

    // unroll 16 (PARALLEL_SCANS_NUM * UNROLL_FACTOR) times, while we have at least 4 input bytes to process.
    while (buf_pos[PARALLEL_SCANS_NUM-1] + UNROLL_FACTOR <= end) {
        // Fastpath - Advance all heads up to 4 chars, as long as they're all on a full state.
        if (CP_LIKELY(parallel_scan_advance_if_full_unroll(bnfa, bnfa_offset, buf_pos))) continue;

        // At least one head is on partial or match - advance all 4 by their type.
        for (i=0; i<PARALLEL_SCANS_NUM; i++) {
            if (bnfa_offset[i] < 0) {
                // Semi-fastpath. When we reach this loop, normally 3 of 4 heads are on a full state.
                bnfa_offset[i] = kiss_thin_nfa_get_next_offset_full(bnfa, bnfa_offset[i], *(buf_pos[i]));
                (buf_pos[i])++;
                continue;
            }

            if (kiss_bnfa_state_type(bnfa, bnfa_offset[i]) == KISS_BNFA_STATE_MATCH) {
                // Handle a match
                kiss_thin_nfa_handle_match_state(runtime, bnfa_offset[i], (u_int)(buf_pos[i] - buffer), len, flags);
                bnfa_offset[i] = kiss_thin_nfa_get_next_offset_match(bnfa, bnfa_offset[i]);
            }
            // Advance to the next state
            bnfa_offset[i] = parallel_scan_advance_one(bnfa, bnfa_offset[i],
                TRANSLATE_CHAR_IF_NEEED(do_char_trans, char_trans_table, *(buf_pos[i])));
            (buf_pos[i])++;
        }
    }

    // Handle remainders (the above loop jumps 4 chars at a time, so it may leave up to 3 unscanned)
    while (buf_pos[PARALLEL_SCANS_NUM-1] < end) {
        // Advance only heads that haven't reached their end position
        for (i=0; i<PARALLEL_SCANS_NUM; i++) {
            if (buf_pos[i] >= head_end_pos[i]) continue;
            if (kiss_bnfa_state_type(bnfa, bnfa_offset[i]) == KISS_BNFA_STATE_MATCH) {
                // Handle a match
                kiss_thin_nfa_handle_match_state(runtime, bnfa_offset[i], (u_int)(buf_pos[i] - buffer), len, flags);
                bnfa_offset[i] = kiss_thin_nfa_get_next_offset_match(bnfa, bnfa_offset[i]);
            }
            // Advance to the next state
            bnfa_offset[i] = parallel_scan_advance_one(bnfa, bnfa_offset[i],
                TRANSLATE_CHAR_IF_NEEED(do_char_trans, char_trans_table, *(buf_pos[i])));
            (buf_pos[i])++;
        }
    }

    // Handle overlap - advance all heads into the next head's range, as long as there's a chance
    // for a match which started in this head's range.
    overlap_head_mask = (1<<(PARALLEL_SCANS_NUM-1))-1;        // All heads except the last
    for (overlap_bytes = 0; overlap_head_mask!=0; overlap_bytes++) {
        // Advance each head (except the last) as long as overlap is needed for it
        for (i=0; i<PARALLEL_SCANS_NUM-1; i++) {
            int my_mask = (1<<i);
            u_int state_depth;

            // Did we stop this head's overlap already?
            if (!(overlap_head_mask & my_mask)) continue;

            // Stop the overlap if the state is not as deep as the overlap, or the buffer ended.
            state_depth = kiss_bnfa_offset_to_depth(runtime->nfa_h, bnfa_offset[i]);
            if ((state_depth <= overlap_bytes) || (buf_pos[i] >= end)) {
                overlap_head_mask &= ~my_mask;
                continue;
            }

            // Advance the state machine, including match handling
            if (kiss_bnfa_state_type(bnfa, bnfa_offset[i]) == KISS_BNFA_STATE_MATCH) {
                // Handle a match
                kiss_thin_nfa_handle_match_state(runtime, bnfa_offset[i], (u_int)(buf_pos[i] - buffer), len, flags);
                bnfa_offset[i] = kiss_thin_nfa_get_next_offset_match(bnfa, bnfa_offset[i]);
            }
            // Advance to the next state
            bnfa_offset[i] = parallel_scan_advance_one(bnfa, bnfa_offset[i],
                TRANSLATE_CHAR_IF_NEEED(do_char_trans, char_trans_table, *(buf_pos[i])));
            (buf_pos[i])++;
        }
    }

    // We may have stopped on a match state. If so - handle and advance
    for (i=0; i<PARALLEL_SCANS_NUM; i++) {
        if (kiss_bnfa_state_type(bnfa, bnfa_offset[i]) == KISS_BNFA_STATE_MATCH) {
            // Handle a match
            kiss_thin_nfa_handle_match_state(runtime, bnfa_offset[i], (u_int)(buf_pos[i] - buffer), len, flags);
            bnfa_offset[i] = kiss_thin_nfa_get_next_offset_match(bnfa, bnfa_offset[i]);
        }
    }

    // The next scan should start at the state where the current scan ended.
    // If multiple heads reached the buffer end, use the one with the lowest index,
    // because it has covered more data than other heads that reached the buffer end.
    for (i=0; i<PARALLEL_SCANS_NUM; i++) {
        if (buf_pos[i] == buf_pos[PARALLEL_SCANS_NUM-1]) {
            runtime->last_bnfa_offset = bnfa_offset[i];
            break;
        }
    }

    return;
}


// Execute a thin NFA on a buffer.
// Parameters:
//   nfa_h             - the NFA handle
//   buf        - a buffer to scan.
//   matches        - output - will be filled with a kiss_pmglob_match_data element for each match.
void
kiss_thin_nfa_exec(KissThinNFA *nfa_h, const Buffer& buf, std::vector<std::pair<uint, uint>> &matches)
{
    struct kiss_bnfa_runtime_s bnfa_runtime;

    dbgAssert(nfa_h != nullptr) << "kiss_thin_nfa_exec() was called with null handle";

    if (buf.size() == 0) {
        return;
    }

    // Set the runtime status structure
    bnfa_runtime.nfa_h = nfa_h;
    bnfa_runtime.last_bnfa_offset = kiss_bnfa_offset_compress(nfa_h->min_bnfa_offset); // The initial state
    bnfa_runtime.matches = &matches;
    bnfa_runtime.scanned_so_far = 0;

    auto segments = buf.segRange();
    for( auto iter = segments.begin(); iter != segments.end(); iter++ ) {
        const u_char * data = iter->data();
        u_int len = iter->size();
        u_int flags = ((iter+1)==segments.end()) ? KISS_PM_EXEC_LAST_BUFF : 0;
        if (nfa_h->flags & KISS_THIN_NFA_USE_CHAR_XLATION) {
            kiss_thin_nfa_exec_one_buf_parallel_ex(&bnfa_runtime, data, len, flags, TRUE, nfa_h->xlation_tab);
        } else {
            kiss_thin_nfa_exec_one_buf_parallel_ex(&bnfa_runtime, data, len, flags, FALSE, nullptr);
        }
        bnfa_runtime.scanned_so_far += len;
    }

    return;
}
