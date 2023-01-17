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

#include <memory>
#include "pm_adaptor.h"
#include "kiss_hash.h"
#include "kiss_thin_nfa_impl.h"
#include "kiss_patterns.h"

// Flag for a Thin NFA state
typedef enum {
    THIN_NFA_STATE_FULL =                0x01,   // We want a full state table for this state
    THIN_NFA_STATE_MATCH =                0x02,  // A matching state
    THIN_NFA_STATE_ROOT =                0x04,   // The root or anchored root state
    THIN_NFA_STATE_MAX_IDENTICAL_CHAR =    0x08, // Maximal sequence of identical characters
    THIN_NFA_STATE_ANCHORED =            0x10,   // A part of the anchored tree
    THIN_NFA_STATE_BUILT_TABLE =         0x20,   // Already built the BNFA transition table
    THIN_NFA_STATE_REACH_FROM_FULL =    0x40,    // The state is reachable from full state
} nfa_thin_state_flags_t;

// A Thin NFA state, or a node in the trie, during compilation time
struct kiss_thin_nfa_state_s {
    u_int state_id;                             // Sequencial number, starting from 0
    nfa_thin_state_flags_t flags;
    u_int depth;                                // Level in the trie
    kiss_thin_nfa_pattern_list_t *ids;          // For finite state, patterns associated with it
    struct kiss_thin_nfa_state_s *bfs_q;        // Use for a BFS iteration on the trie
    struct thin_nfa_comp_s *comp;               // Saves passing this pointer around
    // Outgoing transitions
    struct kiss_thin_nfa_state_s *child;        // First child of this state
    u_int num_trans;                            // Number of transitions
    struct kiss_thin_nfa_state_s *fail_state;
    // Incoming transition
    struct kiss_thin_nfa_state_s *sibling;      // Next child of this state's father
    u_char tran_char;                           // The character that takes us to this state
    // BNFA offset
    kiss_bnfa_offset_t bnfa_offset;             // Where the real state is
    kiss_bnfa_offset_t bnfa_incoming_off;       // Where incoming transitions should jump (possibly a match state)
    // DEBUG ONLY
    const u_char *pattern_text;                 // Points into the user's pattern list. Not null terminated
};
typedef struct kiss_thin_nfa_state_s kiss_thin_nfa_state_t;


// Blocks to hold states . A pretty simple pool mechanism.
// Not very much needed. We currently use it to iterate states by ID order, and for state pointer validation.
#define MAX_THIN_NFA_STATES_BLOCKS            1000
#define KISS_NFA_MAX_STATES_PER_BLOCK         1000
#define KISS_NFA_MAX_STATES_BLOCK_SIZE        (KISS_NFA_MAX_STATES_PER_BLOCK * sizeof(kiss_thin_nfa_state_t))


// When do we want a full state? In the first X tiers (root included) and if more than Y transitions.
u_int kiss_thin_nfa_full_tiers_num_small = 2;  // Old values, for PMs which must remain small
u_int kiss_thin_nfa_full_tiers_num_medium = 3; // Used for VSX / 32bit kernel, where memory is expensive
u_int kiss_thin_nfa_full_tiers_num = 7;        // New value
u_int kiss_thin_nfa_max_partial_trans = 15;    // Can't exceed KISS_BNFA_MAX_TRANS_NUM anyway
u_int kiss_thin_nfa_optimize_contig_chars = 1;


// Character translation table for caseless/digitless comparisons.
//
// The idea:
//  Each character has a canonic character. This can be itself, or another.
//   In a caseless Thin NFA, 'a' and '7' are canonic themselves, 'B' has canonic character 'b'.
//   In a digitless Thin NFA, '7' is not canonic - its canonic character is '0'.
//  Each character is also a member of a group, containing all characters with the same canonic character.
//   In a caseless Thin NFA, 'a' and 'A' are in one group.
//   In a digitless Thin NFA, all digits are in one group.
//  Notice that a single Thin NFA can be caseless, digitless, neither or both.
//
// The data structure:
//  tab - Translates each character into its canonic characer (possibly itself).
//  rev - A linked list of characters belonging to the same group. The character itself
//    is used instead of a pointer. The last character in the group points to the first.
//    Example: For a caseless Thin NFA, rev['a']='A' and rev['A']='a'.
struct thin_nfa_char_trans_tab_s {
    u_char tab[KISS_PM_ALPHABET_SIZE];
    u_char rev[KISS_PM_ALPHABET_SIZE];
};


// Flags for an entire Thin NFA during compilation
typedef enum {
    THIN_NFA_FAIL_STATES_CALCULATED = 0x01,        // Once we set this, we expect all states to have fail states.
    THIN_NFA_ENABLE_ANCHOR_OPT      = 0x02,        // Enable optimization for anochored states
    THIN_NFA_USE_RECURSIVE_COMPILE    = 0x04,      // Build full states recursively. Faster, unsuitable for kernel
} thin_nfa_comp_flags_e;


// A Thin NFA which is under construction. The compiled BNFA is constructed from this later.
struct thin_nfa_comp_s {
    kiss_thin_nfa_state_t *root_state;          // The root state (somewhere inside state_blocks)
    kiss_thin_nfa_state_t *anchored_root_state; // The root for anchored patterns
    u_int full_state_tier_num;                  // How many tiers would be full states?
    u_int state_num;                            // How many states do we have so far
    u_int match_state_num;                      // How many matching states do we have?
    u_int full_state_num;                       // How many full states do we have?
    KissPMError *error;                         // Error to be returned to the user.
    thin_nfa_comp_flags_e flags;
    struct thin_nfa_char_trans_tab_s *xlation_tab;                   // Caseless/digitless translation table
    kiss_thin_nfa_state_t *state_blocks[MAX_THIN_NFA_STATES_BLOCKS]; // Dynamically allocated memory for states
    std::unique_ptr<KissThinNFA> runtime_nfa;                        // The final NFA we're building
    kiss_hash_t patterns_hash;                                       // Pattern array to offset mapping
    kiss_bnfa_offset_t min_bnfa_off, max_bnfa_off;
};


#if defined(DEBUG)
#define KISS_THIN_NFA_DO_VERIFICATIONS
#endif


#define MAX_STATE_NAME_LEN 100
#define MAX_STATE_NAME_BUFS 4


static kiss_thin_nfa_state_t *
kiss_thin_nfa_get_state_by_id(struct thin_nfa_comp_s *nfa_comp, u_int state_id, const char *caller)
{
    u_int block_index;
    u_int index_in_block;
    kiss_thin_nfa_state_t *block;

    // Find the block and the place in the block
    block_index = state_id / KISS_NFA_MAX_STATES_PER_BLOCK;
    index_in_block = state_id % KISS_NFA_MAX_STATES_PER_BLOCK;
    if (block_index >= MAX_THIN_NFA_STATES_BLOCKS) {
        thinnfa_debug_critical(("%s: State %d - invalid block index %d (max %d)\n", caller,
            state_id, block_index, MAX_THIN_NFA_STATES_BLOCKS));
        return NULL;
    }
    block = nfa_comp->state_blocks[block_index];
    if (block == NULL) {
        thinnfa_debug_critical((
            "%s: State %d - block index %d is not allocated yet\n",
            caller,
            state_id,
            block_index
        ));
        return NULL;
    }

    return &block[index_in_block];
}


// DEBUG FUNCTION - return a printable name for the state, in a static buffer.
// Accepts a NULL state.
static const char *
state_name(const kiss_thin_nfa_state_t *state)
{
    static char buffers[MAX_STATE_NAME_BUFS][MAX_STATE_NAME_LEN];
    static u_int next_buf = 0;
    u_int cur_buf;
    char *name, *p;

    if (!state) {
        // Happens when printing the root's fail state
        return "NULL/-1";
    }

    // What's a state's name?
    // Each state represents a prefix of one or more patterns. This prefix is the natural name for the state.
    // We have the pattern text on the state. Its depth tells us how much of it do we need.
    // We add the state ID as a suffix, to prevent ambiguituies (particularly for unprintable characters).

    //Choose a buffer to use. Allows calling several times under a single debug message.
    cur_buf = next_buf;
    if (cur_buf >= MAX_STATE_NAME_BUFS) cur_buf = 0;
    next_buf = cur_buf + 1;
    name = buffers[cur_buf];
    p = name;

    if (state->flags & THIN_NFA_STATE_ANCHORED) {
        // Prefix for anchored states
        *p = '^';
        p++;
    }

    // Fill in the state name. Not null-terminated meanwhile.
    if (state->pattern_text == NULL) {
        const char *state_name;
        // Only the root makes sense. But deal with a missing pattern text anyway
        state_name = (state->flags & THIN_NFA_STATE_ROOT) ? "ROOT" : "INVALID";
        strcpy(p, state_name);
        p += strlen(state_name);
    } else {
        u_int i;
        // Normal state - use the relevant prefix of the pattern text
        for (i=0; (i<state->depth) && (p<name+MAX_STATE_NAME_LEN-10); i++) {
            *p = isprint(state->pattern_text[i]) ? state->pattern_text[i] : '.';
            p++;
        }
    }

    // Append the state ID. Removes ambituities (e.g. for unprintable characters)
    snprintf(p, MAX_STATE_NAME_LEN-(p-name), "/%u", state->state_id);
    name[MAX_STATE_NAME_LEN-1] = '\0';

    return name;
}


#if defined(KISS_THIN_NFA_DO_VERIFICATIONS)

// DEBUG FUNCTION - Verify that a state pointer points to a valid state
static BOOL
is_valid_state_ptr(struct thin_nfa_comp_s *nfa_comp, kiss_thin_nfa_state_t *state, const char *caller)
{
    kiss_thin_nfa_state_t *state_by_id;

    if (!state) {
        thinnfa_debug_critical(("%s: Null state pointer\n", caller));
        return FALSE;
    }

    state_by_id = kiss_thin_nfa_get_state_by_id(nfa_comp, state->state_id, caller);
    if (!state_by_id) {
        return FALSE;
    }

    // Is the state where we expect it to be in the block?
    if (state != state_by_id) {
        thinnfa_debug_critical(("%s: State %p ID %d is invalid - should be at %p\n", caller, state,
            state->state_id, state_by_id));
        return FALSE;
    }

    return TRUE;
}


// DEBUG FUNCTION - Verify a state's transition table
static void
verify_state_ex(struct thin_nfa_comp_s *nfa_comp, kiss_thin_nfa_state_t *state, const char *caller)
{
    kiss_thin_nfa_state_t *child, *prev_child;
    u_int actual_tran_num;

    // Is the pointer itself OK?
    KISS_ASSERT(is_valid_state_ptr(nfa_comp, state, caller),
        ("%s: Invalid state pointer %p\n", caller, state));

    // Go over the transition table
    actual_tran_num = 0;
    prev_child = NULL;
    for (child = state->child; child != NULL; child = child->sibling) {
        // Valid pointer?
        KISS_ASSERT(is_valid_state_ptr(nfa_comp, child, caller),
            ("%s: State %s(%p) contains an invalid child %p after %02x\n", caller, state_name(state), state,
            child, prev_child ? prev_child->tran_char : 0));

        // Sorted in ascending order?
        KISS_ASSERT(!prev_child || prev_child->tran_char < child->tran_char,
            ("%s: State %s(%p) transition %02x -> %s after %02x -> %s\n", caller,
            state_name(state), state,
            child->tran_char, state_name(child),
            prev_child->tran_char, state_name(prev_child)));

        actual_tran_num++;
        if (actual_tran_num > state->num_trans) {
            // We may be looping
            break;
        }
        prev_child = child;
    }

    // Counter matches list?
    KISS_ASSERT(actual_tran_num == state->num_trans,
        ("%s: State %s(%p) has %d transitions, but it should have %d\n", caller, state_name(state), state,
        actual_tran_num, state->num_trans));

    // Fail state?
    if (nfa_comp->flags & THIN_NFA_FAIL_STATES_CALCULATED) {
        if (state->fail_state == NULL) {
            KISS_ASSERT(state == nfa_comp->root_state, ("%s: State %s has no fail state, but it is not root",
                caller, state_name(state)));
        } else {
            KISS_ASSERT(
                is_valid_state_ptr(nfa_comp, state->fail_state, caller),
                "%s: State %s has an invalid fail state %p\n",
                caller,
                state_name(state),
                state->fail_state
            );
        }
    }
}


// Use this for sanity test on a state
#define verify_state(nfa_comp, state) verify_state_ex(nfa_comp, state, FILE_LINE)

#else // KISS_THIN_NFA_DO_VERIFICATIONS

// Verifications disabled
#define verify_state(nfa_comp, state)

#endif // KISS_THIN_NFA_DO_VERIFICATIONS


// Mark that a state needs to be full
static void
make_state_full(kiss_thin_nfa_state_t *state)
{
    if (state->flags & THIN_NFA_STATE_FULL) return;
    ENUM_SET_FLAG(state->flags, THIN_NFA_STATE_FULL);
    state->comp->full_state_num++;
}


// Mark that a state is matching
static void
make_state_matching(kiss_thin_nfa_state_t *state)
{
    if (state->flags & THIN_NFA_STATE_MATCH) return;
    ENUM_SET_FLAG(state->flags, THIN_NFA_STATE_MATCH);
    state->comp->match_state_num++;
}


// Allocate an empty state on an NFA.
// Initializes all fields to defaults.
static kiss_thin_nfa_state_t *
kiss_thin_nfa_state_create(
    struct thin_nfa_comp_s *nfa_comp,
    u_int depth,
    const u_char *pattern_text,
    nfa_thin_state_flags_t flags
)
{
    static const char rname[] = "kiss_thin_nfa_state_create";
    u_int state_id;
    u_int block_index;
    u_int index_in_block;
    kiss_thin_nfa_state_t *block;
    kiss_thin_nfa_state_t *state;

    // Find the next ID and the block it should be in
    state_id = nfa_comp->state_num;
    block_index    = state_id / KISS_NFA_MAX_STATES_PER_BLOCK;
    index_in_block = state_id % KISS_NFA_MAX_STATES_PER_BLOCK;

    thinnfa_debug_extended(("%s: Adding state %d depth %d\n", rname, state_id, depth));

    // No more possible blocks?
    if (block_index >= MAX_THIN_NFA_STATES_BLOCKS) {
        thinnfa_debug_err(("%s: State %d in block %d exceeds the limit %d\n", rname,
            state_id, block_index, MAX_THIN_NFA_STATES_BLOCKS));
        return NULL;
    }

    // Allocate the block if needed (first state in the block)
    block = nfa_comp->state_blocks[block_index];
    if (block == NULL) {
        block = (kiss_thin_nfa_state_t *)fw_kmalloc_ex(KISS_NFA_MAX_STATES_BLOCK_SIZE, rname, FW_KMEM_SLEEP);
        if (block == NULL) {
            thinnfa_debug_err(("%s: Failed to allocate a state block size %lu for the state %u\n", rname,
                KISS_NFA_MAX_STATES_BLOCK_SIZE, state_id));
            return NULL;
        }
        nfa_comp->state_blocks[block_index] = block;
    }

    // Initialize the state
    state = &block[index_in_block];

    state->state_id = state_id;
    state->flags = flags;
    state->ids = NULL;
    state->bfs_q = NULL;
    state->child = NULL;
    state->num_trans = 0;
    state->fail_state = NULL;
    state->sibling = NULL;
    state->tran_char = '\0';    // Will be modified, except for the root
    state->pattern_text = pattern_text;
    state->depth = depth;
    state->comp = nfa_comp;
    state->bnfa_offset = KISS_BNFA_OFFSET_INVALID;
    state->bnfa_incoming_off = KISS_BNFA_OFFSET_INVALID;

    // Do we want a full state? kiss_thin_nfa_full_tiers_num=2 means tiers 0 and 1, i.e. the root plus one, are full.
    if (state->flags & THIN_NFA_STATE_ROOT) {
        // The root must be full, because it has no fail state.
        // The anchored root (if exists) is the first state, and must be full, for the bnfa_full_state_size
        //  condition to work.
        make_state_full(state);
    } else if (depth < nfa_comp->full_state_tier_num && !(state->flags & THIN_NFA_STATE_ANCHORED)) {
        make_state_full(state);
    }

    // Advance the counter
    nfa_comp->state_num++;

    return state;
}


// Release all resources on a state structure.
// Doesn't release the states, because it's part of a state block.
static void
kiss_thin_nfa_state_free(kiss_thin_nfa_state_t *state)
{
    // Clean up the pattern list
    if (state->ids) {
        kiss_thin_nfa_free_pattern_ids(state->ids);
        state->ids = NULL;
    }

    return;
}


// Returns the following state, by ID order.
//   With prev==NULL, returns the first state.
//   With prev!=NULL, returns the next.
//   If prev is the last state, returns NULL.
static kiss_thin_nfa_state_t *
kiss_thin_nfa_get_subsequent_state(struct thin_nfa_comp_s *nfa_comp, kiss_thin_nfa_state_t *prev)
{
    static const char rname[] = "kiss_thin_nfa_get_subsequent_state";
    u_int state_id;

    // Find the next state's ID
    state_id = prev ? prev->state_id + 1 : 0;
    if (state_id >= nfa_comp->state_num) {
        // prev was the last state.
        return NULL;
    }

    // Get the state pointer
    return kiss_thin_nfa_get_state_by_id(nfa_comp, state_id, rname);
}


// Find the transition for a given character from a given state.
// If no transition found, returns NULL and does not check the fail state.
static kiss_thin_nfa_state_t *
kiss_thin_nfa_comp_get_next_state(kiss_thin_nfa_state_t *state, u_char ch)
{
    static const char rname[] = "kiss_thin_nfa_comp_get_next_state";
    kiss_thin_nfa_state_t *child;

    verify_state(state->comp, state);

    // Find the child in the list
    for (child = state->child; child != NULL; child = child->sibling) {
        u_char tran_ch = child->tran_char;

        if (tran_ch == ch) {
            thinnfa_debug_extended((
                "%s: Found transition from the state %s by 0x%02x to %s\n",
                rname,
                state_name(state),
                ch,
                state_name(child)
            ));
            return child;
        }

        // The list is sorted, so we don't need to look beyond the character.
        if (tran_ch > ch) break;
    }

    thinnfa_debug_extended(("%s: No transition from the state %s by 0x%02x\n", rname, state_name(state), ch));

    return NULL;
}


// Mark a state as finite and accepting a given kiss_thin_nfa_pattern_t pattern
static kiss_ret_val
kiss_thin_nfa_state_set_match(kiss_thin_nfa_state_t *state, const kiss_thin_nfa_pattern_t *pat_info)
{
    static const char rname[] = "kiss_thin_nfa_state_set_match";

    verify_state(state->comp, state);

    // Add the pattern to this state's pattern list
    if (kiss_thin_nfa_add_pattern_id(&(state->ids), pat_info) != KISS_OK) {
        thinnfa_debug_err((
            "%s: Could not add the 'pattern_id' %d to the final state %s\n",
            rname,
            pat_info->id,
            state_name(state)
        ));
        return KISS_ERROR;
    }

    thinnfa_debug((
        "Setting state %s as the matching state for the 'pattern_id' %d\n",
        state_name(state),
        pat_info->id
    ));
    make_state_matching(state);

    return KISS_OK;
}


// Mark a state as finite, and accepting a given kiss_pmglob_string pattern
static kiss_ret_val
kiss_thin_nfa_state_set_match_pattern(kiss_thin_nfa_state_t *state, const kiss_pmglob_string_s *pattern)
{
    kiss_thin_nfa_pattern_t pat_info;

    pat_info.id                    = kiss_pmglob_string_get_id(pattern);
    pat_info.pattern_id_flags    = kiss_pmglob_string_get_flags(pattern);
    pat_info.len                = kiss_pmglob_string_get_size(pattern);

    return kiss_thin_nfa_state_set_match(state, &pat_info);
}


// Copy the list of accepted patterns from one state to another.
// The destination state can already have patterns, and the lists would be concatenated.
static kiss_ret_val
kiss_thin_nfa_state_copy_match_ids(kiss_thin_nfa_state_t *dst, kiss_thin_nfa_state_t *src)
{
    static const char rname[] = "kiss_thin_nfa_state_copy_match_ids";
    kiss_thin_nfa_pattern_list_t *curr_id;

    verify_state(src->comp, src);
    verify_state(dst->comp, dst);

    thinnfa_debug(("%s: Copying the match IDs from %s to %s\n", rname, state_name(src), state_name(dst)));

    // traversing on the state_src 'ids' adding each one to 'state_dst' list
    for(curr_id = src->ids; curr_id; curr_id = curr_id->next) {
        if (kiss_thin_nfa_state_set_match(dst, &curr_id->pattern) != KISS_OK) {
            thinnfa_debug_err((
                "%s: Failed to set the ID %d on the state %s\n",
                rname,
                curr_id->pattern.id,
                state_name(dst)
            ));

            // NOTE: We don't release the IDs we have added. Compilation will fail and clean up anyway.
            return KISS_ERROR;
        }
    }

    return KISS_OK;
}


// Destroy the NFA we're compiling
static void
kiss_thin_nfa_comp_destroy(struct thin_nfa_comp_s *nfa_comp)
{
    static const char rname[] = "kiss_thin_nfa_comp_destroy";
    u_int i;
    kiss_thin_nfa_state_t *state;

    thinnfa_debug_major(("%s: Destroying the compilation information structure\n", rname));

    // Cleanup whatever data we have on the states.
    for (state = nfa_comp->root_state; state != NULL; state = kiss_thin_nfa_get_subsequent_state(nfa_comp, state)) {
        kiss_thin_nfa_state_free(state);
    }

    // Free the state blocks and transition blocks
    for (i = 0; i < MAX_THIN_NFA_STATES_BLOCKS; i++) {
        if (nfa_comp->state_blocks[i] != NULL) {
            fw_kfree(nfa_comp->state_blocks[i], KISS_NFA_MAX_STATES_BLOCK_SIZE, rname);
            nfa_comp->state_blocks[i] = NULL;
        }
    }

    if (nfa_comp->xlation_tab!= NULL) {
        fw_kfree(nfa_comp->xlation_tab, sizeof(*(nfa_comp->xlation_tab)), rname);
        nfa_comp->xlation_tab= NULL;
    }

    nfa_comp->runtime_nfa.reset(nullptr);

    if (nfa_comp->patterns_hash) {
        kiss_hash_destroy(nfa_comp->patterns_hash);
        nfa_comp->patterns_hash = NULL;
    }

    fw_kfree(nfa_comp, sizeof(*nfa_comp), rname);
}


// Allocate an empty thin NFA compilation data structure.
static struct thin_nfa_comp_s *
kiss_thin_nfa_comp_create(KissPMError *error)
{
    static const char rname[] = "kiss_thin_nfa_comp_create";
    struct thin_nfa_comp_s *nfa_comp = NULL;

    thinnfa_debug_major(("%s: Allocating the compilation information structure\n", rname));

    // Allocate and initialize the compilation temporary structure
    nfa_comp = (struct thin_nfa_comp_s *)fw_kmalloc(sizeof(*nfa_comp), rname);
    if (!nfa_comp) {
        thinnfa_debug_err(("%s: Failed to allocate 'nfa_comp'\n", rname));
        goto failure;
    }
    bzero((void *)nfa_comp, sizeof(*nfa_comp));

    nfa_comp->error = error;

    // Build the root state
    nfa_comp->root_state = kiss_thin_nfa_state_create(nfa_comp, 0, NULL, THIN_NFA_STATE_ROOT);
    if (nfa_comp->root_state == NULL) {
        thinnfa_debug_err(("%s: Failed to create the root state\n", rname));
        goto failure;
    }

    return nfa_comp;

failure:

    if (nfa_comp != NULL) {
        kiss_thin_nfa_comp_destroy(nfa_comp);
    }
    return NULL;

}


// Specify the error for failed Thin NFA compilation
static void
kiss_thin_nfa_set_comp_error(struct thin_nfa_comp_s *nfa_comp, const char *err_text)
{
    // We always use "internal", which is appropriate for both logical errors and resource shortage.
    // We don't specify a pattern, because nothing is really pattern specific.
    kiss_pm_error_set_details(nfa_comp->error, KISS_PM_ERROR_INTERNAL, err_text);
}


// Initialize a translation table for caseless/digitless comparison.
// According to compilation flags, builds a table to translate each character.
static kiss_ret_val
kiss_thin_nfa_create_xlation_tab(struct thin_nfa_comp_s *nfa_comp, int pm_comp_flags)
{
    static const char rname[] = "kiss_thin_nfa_create_xlation_tab";
    enum kiss_pmglob_char_xlation_flags_e xlation_flags;

    // Figure out which translations we need
    xlation_flags = KISS_PMGLOB_CHAR_XLATION_NONE;
    if (pm_comp_flags & KISS_PM_COMP_CASELESS) {
        ENUM_SET_FLAG(xlation_flags, KISS_PMGLOB_CHAR_XLATION_CASE);
    }
    if (pm_comp_flags & KISS_PM_COMP_DIGITLESS) {
        ENUM_SET_FLAG(xlation_flags, KISS_PMGLOB_CHAR_XLATION_DIGITS);
    }
    if (xlation_flags == KISS_PMGLOB_CHAR_XLATION_NONE) {
        // No translation needed
        nfa_comp->xlation_tab = NULL;
        return KISS_OK;
    }

    thinnfa_debug_major(("%s: Using%s%s translation table\n", rname,
        (xlation_flags&KISS_PMGLOB_CHAR_XLATION_CASE)   ? " caseless"  : "",
        (xlation_flags&KISS_PMGLOB_CHAR_XLATION_DIGITS) ? " digitless" : ""));

    // Allocate a translation table
    nfa_comp->xlation_tab = (struct thin_nfa_char_trans_tab_s *)fw_kmalloc(sizeof(*(nfa_comp->xlation_tab)), rname);
    if (!nfa_comp->xlation_tab) {
        thinnfa_debug_err(("%s: Failed to allocate the translation table\n", rname));
        return KISS_ERROR;
    }

    // Build the mapping - normal and reverse
    kiss_pmglob_char_xlation_build(xlation_flags, nfa_comp->xlation_tab->tab);
    kiss_pmglob_char_xlation_build_reverse(nfa_comp->xlation_tab->tab, nfa_comp->xlation_tab->rev);

    return KISS_OK;
}


// Translate a character to canonic form, if a translation table is defined.
static CP_INLINE u_char
kiss_thin_nfa_xlate_char(struct thin_nfa_comp_s *nfa_comp, u_char ch)
{
    if (!nfa_comp->xlation_tab) return ch;
    return nfa_comp->xlation_tab->tab[ch];
}


#if defined(KISS_THIN_NFA_DO_VERIFICATIONS) && !defined(KERNEL)

// DEBUG FUNCTION - uses a simple&slow algorithm to verify the result of kiss_thin_nfa_are_trans_contained.
// Can't run in the kernel because of the large stack consumption.
static void
verify_trans_contains_(
    kiss_thin_nfa_state_t *state_contains,
    kiss_thin_nfa_state_t *state_included,
    BOOL should_contain
)
{
    kiss_thin_nfa_state_t *trans_contains[KISS_PM_ALPHABET_SIZE];
    kiss_thin_nfa_state_t *trans_included[KISS_PM_ALPHABET_SIZE];
    kiss_thin_nfa_state_t *child;
    u_int i;
    int mismatch_pos;

    // Fill in both transition tables
    bzero(trans_contains, sizeof(trans_contains));
    for (child = state_contains->child; child != NULL; child = child->sibling) {
        trans_contains[child->tran_char] = child;
    }
    bzero(trans_included, sizeof(trans_included));
    for (child = state_included->child; child != NULL; child = child->sibling) {
        trans_included[child->tran_char] = child;
    }

    // Go over the table, looking for a character that's in "included" but not in "contains".
    mismatch_pos = -1;
    for (i=0; i<KISS_PM_ALPHABET_SIZE; i++) {
        if (trans_included[i] != NULL && trans_contains[i] == NULL) {
            mismatch_pos = i;
            break;
        }
    }
    if (mismatch_pos < 0) {
        // No mismatch - really contains
        KISS_ASSERT(
            should_contain,
            ("State %s contains %s, but the kiss_thin_nfa_are_trans_contained says it does not",
            state_name(state_contains),
            state_name(state_contains))
        );
    } else {
        // Mismatch - doesn't contain
        KISS_ASSERT(
            !should_contain,
            ("State %s does not contain %s (%02x -> %s), but the kiss_thin_nfa_are_trans_contained says it does",
            state_name(state_contains),
            state_name(state_included),
            (u_char)mismatch_pos,
            state_name(trans_included[i]))
        );
    }
}


#define verify_trans_contains(state_contains, state_included, expected)    \
    verify_trans_contains_(state_contains, state_included, expected)

#else // KISS_THIN_NFA_DO_VERIFICATIONS

#define verify_trans_contains(state_contains, state_included, expected)

#endif // KISS_THIN_NFA_DO_VERIFICATIONS


// Do all transactions of "included" also exist in "contains"?
static BOOL
kiss_thin_nfa_are_trans_contained(kiss_thin_nfa_state_t *state_contains, kiss_thin_nfa_state_t *state_included)
{
    kiss_thin_nfa_state_t *included_child, *contains_child;

    verify_state(state_contains->comp, state_contains);
    verify_state(state_included->comp, state_included);

    if (state_contains->num_trans < state_included->num_trans) {
        // "contains" has fewer states - it can't include all "included"
        verify_trans_contains(state_contains, state_included, FALSE);
        return FALSE;
    }

    // Advance both included_child and contains_child, to iterate both transition tables.
    // Keep them in sync - included_child passes children one by one, and contains_child is advanced
    //  to the same transition character at each step.
    contains_child = state_contains->child;

    // Go over the transitions in "included", see if they're in "contained"
    for (included_child = state_included->child; included_child != NULL; included_child = included_child->sibling) {
        // Advance "tran_contains" until we reach the character we want
        for (; contains_child != NULL; contains_child = contains_child->sibling) {
            if (contains_child->tran_char >= included_child->tran_char) break;
        }

        // Do we have this character in "contains"?
        if (contains_child == NULL || contains_child->tran_char != included_child->tran_char) {
            // This character doesn't exist in state_contains
            verify_trans_contains(state_contains, state_included, FALSE);
            return FALSE;
        }
    }

    verify_trans_contains(state_contains, state_included, TRUE);
    return TRUE;
}


// Get the root state, or the anchored root state, as appropriate for the pattern.
static kiss_thin_nfa_state_t *
kiss_thin_nfa_get_root_state(struct thin_nfa_comp_s *nfa_comp, int anchored)
{
    static const char rname[] = "kiss_thin_nfa_get_root_state";

    if (!anchored || !(nfa_comp->flags & THIN_NFA_ENABLE_ANCHOR_OPT)) {
        thinnfa_debug(("%s: Using normal root: %s, feature %s\n", rname,
            anchored?"anchored":"not anchored", (nfa_comp->flags & THIN_NFA_ENABLE_ANCHOR_OPT)?"enabled":"disabled"));
        return nfa_comp->root_state;
    }

    if (!nfa_comp->anchored_root_state) {
        // Lazy creation of the anchored root state
        nfa_thin_state_flags_t flags = THIN_NFA_STATE_ROOT;
        ENUM_SET_FLAG(flags, THIN_NFA_STATE_ANCHORED);
        thinnfa_debug(("%s: Creating a new anchored root\n", rname));
        nfa_comp->anchored_root_state = kiss_thin_nfa_state_create(nfa_comp, 0, NULL, flags);
        if (nfa_comp->anchored_root_state == NULL) {
            thinnfa_debug_err(("%s: Failed to create the anchored root state\n", rname));
            return NULL;
        }
    }

    thinnfa_debug(("%s: Returning the anchored root (%d)\n", rname, nfa_comp->anchored_root_state->state_id));
    return nfa_comp->anchored_root_state;
}


// Find the state in the trie, which represents the longest prefix of a given string.
static kiss_thin_nfa_state_t *
kiss_thin_nfa_find_longest_prefix(struct thin_nfa_comp_s *nfa_comp, const u_char *text, u_int len, int anchored)
{
    u_int offset;
    kiss_thin_nfa_state_t *state;

    // Following the path labeled by chars in 'pattern' (skip the states which already exist)
    state = kiss_thin_nfa_get_root_state(nfa_comp, anchored);
    if (!state) return NULL;
    for (offset = 0; offset < len; offset++) {
        kiss_thin_nfa_state_t *next_state;
        u_char ch = kiss_thin_nfa_xlate_char(nfa_comp, text[offset]);

        verify_state(nfa_comp, state);

        // Do we have a node for the next character?
        next_state = kiss_thin_nfa_comp_get_next_state(state, ch);

        if (next_state == NULL) {
            // No next state - this is as far as we go
            break;
        } else {
            state = next_state;
        }
    }

    return state;
}


// Add a newly allocated state to the trie. Keep the transition list sorted.
static void
kiss_thin_nfa_add_transition(kiss_thin_nfa_state_t *parent, u_char tran_char, kiss_thin_nfa_state_t *new_child)
{
    static const char rname[] = "kiss_thin_nfa_add_transition";
    kiss_thin_nfa_state_t **child_p;

    // Go over existing children and find the place to add the transition
    for (child_p = &parent->child; *child_p != NULL; child_p = &(*child_p)->sibling) {
        kiss_thin_nfa_state_t *child = *child_p;
        if (child->tran_char > tran_char) {
            // Add before this one
            break;
        }
    }

    // Add the transition
    new_child->sibling = *child_p;
    *child_p = new_child;
    new_child->tran_char = tran_char;
    parent->num_trans++;

    thinnfa_debug_extended(("%s: Added transition from %s by 0x%2x to %s\n", rname,
        state_name(parent), tran_char, state_name(new_child)));

    if (parent->num_trans > MIN(kiss_thin_nfa_max_partial_trans, KISS_BNFA_MAX_TRANS_NUM)) {
        thinnfa_debug((
            "%s: State %s has %d transitions - making it full\n",
            rname,
            state_name(parent),
            parent->num_trans
        ));
        make_state_full(parent);
    }

    // Track states which represent a maximal sequence of identical characters
    if ((parent->flags & THIN_NFA_STATE_ROOT) && !(parent->flags & THIN_NFA_STATE_ANCHORED)) {
        // Single character - all characters are identical
        ENUM_SET_FLAG(new_child->flags, THIN_NFA_STATE_MAX_IDENTICAL_CHAR);
    } else if ((parent->flags & THIN_NFA_STATE_MAX_IDENTICAL_CHAR) && (parent->tran_char == tran_char)) {
        // The child, not the parent, is now the longest
        ENUM_UNSET_FLAG(parent->flags, THIN_NFA_STATE_MAX_IDENTICAL_CHAR);
        ENUM_SET_FLAG(new_child->flags, THIN_NFA_STATE_MAX_IDENTICAL_CHAR);
    }
}


// Add a pattern to the trie, which would generate the Thin NFA.
// Upon failure, doesn't clean up states it may have created. Will be cleaned up when destroying nfa_comp.
static kiss_ret_val
kiss_thin_nfa_add_pattern_to_trie(struct thin_nfa_comp_s *nfa_comp, const kiss_pmglob_string_s *sm_cur_pattern)
{
    static const char rname[] = "kiss_thin_nfa_add_pattern_to_trie";
    const u_char *pattern_text;
    u_int pattern_len;
    u_int i;
    kiss_thin_nfa_state_t *current_state;
    int anchored_pattern;

    pattern_text = kiss_pmglob_string_get_pattern(sm_cur_pattern);
    pattern_len = kiss_pmglob_string_get_size(sm_cur_pattern);
    anchored_pattern = kiss_pmglob_string_get_flags(sm_cur_pattern) & KISS_PM_LSS_AT_BUF_START;

    thinnfa_debug(("%s: Adding the pattern: %s flags=%x\n", rname, kiss_pmglob_string_to_debug_charp(sm_cur_pattern),
        kiss_pmglob_string_get_flags(sm_cur_pattern)));

    // How much of this pattern do we already have in the tree?
    current_state = kiss_thin_nfa_find_longest_prefix(nfa_comp, pattern_text, pattern_len, anchored_pattern);
    if (!current_state) return KISS_ERROR;        // Messages printed inside

    thinnfa_debug(("%s: State %s (flags %x) represents the longest prefix at the offset %d/%d\n", rname,
        state_name(current_state), current_state->flags, current_state->depth, pattern_len));

    // Go over the remaining bytes (if any) and add more states
    for (i = current_state->depth; i < pattern_len; i++) {
        kiss_thin_nfa_state_t *new_state;
        u_char ch;

        // Create a new state. Depth i+1, because the first character (i=0) is at depth 1.
        new_state = kiss_thin_nfa_state_create(nfa_comp, i+1, pattern_text,
            (nfa_thin_state_flags_t)(current_state->flags & THIN_NFA_STATE_ANCHORED));
        if (!new_state) {
            thinnfa_debug_err(("%s: Failed to allocate a new state\n", rname));
            kiss_thin_nfa_set_comp_error(nfa_comp, "Failed to allocate a new state");
            return KISS_ERROR;
        }

        // Add a transition into the new state
        ch = kiss_thin_nfa_xlate_char(nfa_comp, pattern_text[i]);
        kiss_thin_nfa_add_transition(current_state, ch, new_state);

        thinnfa_debug(("%s: Added new state+transition %s -> %s by 0x%02x offset %d\n", rname,
            state_name(current_state), state_name(new_state), ch, i));

        verify_state(nfa_comp, current_state);

        // Add the following states after this one
        current_state = new_state;
    }

    // Set state as finite and add the pattern ID to the list of patterns which this state accepts.
    // Note: It's OK if the state isn't one we just added. E.g. the new pattern is a prefix of an existing one.
    if (kiss_thin_nfa_state_set_match_pattern(current_state, sm_cur_pattern) != KISS_OK) {
        thinnfa_debug_err((
            "%s: Failed to save the pattern information for the state %s\n",
            rname,
            state_name(current_state)
        ));
        kiss_thin_nfa_set_comp_error(nfa_comp, "Failed to save the pattern information for the state");
        return KISS_ERROR;
    }

    return KISS_OK;
}


// Find the transition from a state by a character, considering fail states.
// The state should alrady have its fail state calculated.
//
// Note: kiss_bnfa_build_full_trans_table may pass from_state=NULL. The result is returning the root, which is OK.
static kiss_thin_nfa_state_t *
kiss_thin_nfa_calc_transition(struct thin_nfa_comp_s *nfa_comp, kiss_thin_nfa_state_t *from_state, u_char tran_char)
{
    static const char rname[] = "kiss_thin_nfa_calc_transition";
    kiss_thin_nfa_state_t *state;

    // Go down the fail state chain, until we find a transition.
    for (state = from_state; state != NULL; state = state->fail_state) {
        kiss_thin_nfa_state_t *next_state;

        // Look up in this state's transition table
        next_state = kiss_thin_nfa_comp_get_next_state(state, tran_char);
        if (next_state != NULL) {
            if (state == from_state) {
                thinnfa_debug_extended(("%s: Found transition from %s by 0x%02x to %s\n", rname,
                    state_name(from_state), tran_char, state_name(next_state)));
            } else {
                thinnfa_debug_extended((
                    "%s: Found transition from %s by 0x%02x to %s using the fail state %s\n",
                    rname,
                    state_name(from_state),
                    tran_char,
                    state_name(next_state),
                    state_name(state)
                ));
            }
            return next_state;
        }
    }

    // We've gone down to the root, and found nothing - so the next state is the root.
    thinnfa_debug_extended(("%s: No transition from %s by 0x%02x - going to root\n", rname,
        state_name(from_state), tran_char));
    return nfa_comp->root_state;
}


// A callback function prototype for kiss_thin_nfa_iterate_trans
typedef kiss_ret_val (*kiss_thin_nfa_iterate_trans_cb)(kiss_thin_nfa_state_t *from_state,
    u_char tran_char, kiss_thin_nfa_state_t *to_state);


// Iterate all the transitions in the trie, in BFS order.
// Note: The callback will be called once per transition, i.e. once per state, except for the initial state.
static kiss_ret_val
kiss_thin_nfa_iterate_trans_bfs(struct thin_nfa_comp_s *nfa_comp, kiss_thin_nfa_iterate_trans_cb iter_cb)
{
    static const char rname[] = "kiss_thin_nfa_iterate_trans_bfs";
    kiss_thin_nfa_state_t *bfs_q_head, *bfs_q_tail;

    thinnfa_debug(("%s: Starting BFS iteration, %d states\n", rname, nfa_comp->state_num));

    // This queue contains states, whose children we want to iterate.
    // We start with the root state followed by the anchored root state.
    bfs_q_head = nfa_comp->root_state;
    bfs_q_head->bfs_q = NULL;
    bfs_q_tail = bfs_q_head;
    if (nfa_comp->anchored_root_state) {
        bfs_q_tail->bfs_q = nfa_comp->anchored_root_state;
        nfa_comp->anchored_root_state->bfs_q = NULL;
        bfs_q_tail = nfa_comp->anchored_root_state;
    }

    // Dequeue each of the states, call the iterator for each transition and enqueue the children
    while (bfs_q_head != NULL) {
        kiss_thin_nfa_state_t *from_state;
        kiss_thin_nfa_state_t *to_state;

        // Dequeue a state from the head
        from_state = bfs_q_head;
        bfs_q_head = from_state->bfs_q;
        if (bfs_q_head == NULL) bfs_q_tail = NULL;

        thinnfa_debug_extended((
            "%s: Got the state %s with %d children\n",
            rname,
            state_name(from_state),
            from_state->num_trans
        ));

        // Go over the state's transitions
        for (to_state = from_state->child; to_state != NULL; to_state = to_state->sibling) {
            thinnfa_debug_extended((
                "%s: Got the child state %s at the depth %d\n",
                rname,
                state_name(to_state),
                to_state->depth
            ));

            // Call the iterator function
            if (iter_cb(from_state, to_state->tran_char, to_state) != KISS_OK) {
                return KISS_ERROR;
            }

            // No need to enqueue states with no children
            if (to_state->num_trans == 0) continue;

            // Enqueue the next state, so we'd iterate its transitions too
            to_state->bfs_q = NULL;
            if (bfs_q_tail != NULL) {
                bfs_q_tail->bfs_q = to_state;
            } else {
                bfs_q_head = to_state;
            }
            bfs_q_tail = to_state;
        }
    }

    return KISS_OK;
}


// Set a state's fail state.
// To calculate this, we need the state's parent, and the character that takes us from the parent to the current.
// The parent's fail state must be calculated already.
static kiss_ret_val
kiss_thin_nfa_set_fail_state(kiss_thin_nfa_state_t *parent, u_char tran_char, kiss_thin_nfa_state_t *state)
{
    static const char rname[] = "kiss_thin_nfa_set_fail_state";
    kiss_thin_nfa_state_t *fail_state;

    // Calculate the fail state.
    // The same character that takes us from parent to state would take us from parent->fail_state to state->fail_state
    fail_state = kiss_thin_nfa_calc_transition(state->comp, parent->fail_state, tran_char);
    state->fail_state = fail_state;

    thinnfa_debug(("%s: The fail state of %s is %s (parent %s, parent->fail_state %s, char %02x)\n", rname,
        state_name(state), state_name(fail_state), state_name(parent),
        state_name(parent->fail_state), tran_char));


    // If a state's fail state is finite, so is the state itself.
    // This is because the fail state represents a suffix of the state, which is included in
    //    the suffix the state represents. If the shorter suffix is a match, so is the longer one.
    // Example - The fail state of "abc" is "bc" (if it exists). If "bc" is a match, then so is "abc".
    if (fail_state->flags & THIN_NFA_STATE_MATCH) {
        thinnfa_debug(("%s: Fail state %s is finite - so is %s\n", rname,
            state_name(fail_state), state_name(state)));
        if (kiss_thin_nfa_state_copy_match_ids(state, fail_state)) {
            thinnfa_debug_err((
                "%s: Failed to copy the pattern IDs from %s to %s\n",
                rname,
                state_name(fail_state),
                state_name(state)
            ));
            kiss_thin_nfa_set_comp_error(state->comp, "Failed to copy the pattern IDs");
            return KISS_ERROR;
        }
    }

    // This isn't related to calculating fail states. It should be done after the trie was built, but before
    // starting BNFA construction.
    if (kiss_thin_nfa_optimize_contig_chars && (state->flags & THIN_NFA_STATE_MAX_IDENTICAL_CHAR)) {
        // Optimization for identical character sequences. States which represent a maximal sequence of the same
        // characters will be full. So for a long sequence of a single character, we'll always be in a full state.
        // Great for the performance lab.
        thinnfa_debug((
            "%s: State %s is a maximal identical character sequence - making it full\n",
            rname,
            state_name(state)
        ));
        make_state_full(state);
    }

    return KISS_OK;
}


// See if we can find a better fail state for a state.
// If the fail state contains only transitions the original state has anyway, we can use its fail state instead.
static kiss_thin_nfa_state_t *
kiss_thin_nfa_find_better_fail_state(kiss_thin_nfa_state_t *state)
{
    kiss_thin_nfa_state_t *fail_state;

    if (!state->fail_state) return NULL;

    // Go down the fail state chain.
    // Keep going as long as the states contain only transitions the current state has anyway.
    for (fail_state = state->fail_state; fail_state->fail_state != NULL; fail_state = fail_state->fail_state) {

        verify_state(state->comp, fail_state);

        if (fail_state->flags & THIN_NFA_STATE_FULL) {
            // Full state - failing to it will always give us the answer.
            break;
        }

        if (!kiss_thin_nfa_are_trans_contained(state, fail_state)) {
            // This state has transitions that the current state doesn't - we must fail to it,
            // not lower.
            break;
        }
    }

    return fail_state;
}


// Change fail states to go faster up the tree, if possible.
// Normally, a fail state points one level upward. But sometimes it can be more upward.
//
// Note: This must be done after kiss_thin_nfa_set_fail_state was called for all states. This is because
//  kiss_thin_nfa_set_fail_state uses the parent's fail state to calculate the child's. If the parent's fail stae
//  was "reduced", we'll get the wrong fail state for the child.
static void
kiss_thin_nfa_reduce_fail_states(struct thin_nfa_comp_s *nfa_comp)
{
    static const char rname[] = "kiss_thin_nfa_reduce_fail_states";
    kiss_thin_nfa_state_t *state;

    for (state = nfa_comp->root_state; state != NULL; state = kiss_thin_nfa_get_subsequent_state(nfa_comp, state)) {
        kiss_thin_nfa_state_t *fail_state;

        if (state->flags & THIN_NFA_STATE_FULL) {
            // A full state's fail state isn't interesting
            continue;
        }

        fail_state = kiss_thin_nfa_find_better_fail_state(state);
        if (fail_state != state->fail_state) {
            // We have a better fail state
            thinnfa_debug(("%s: Changing the fail state of %s from %s to %s\n", rname,
                state_name(state), state_name(state->fail_state), state_name(fail_state)));
            state->fail_state = fail_state;
        }
    }
}


// Calculate fail states for all states.
static kiss_ret_val
kiss_thin_nfa_calc_fail_states(struct thin_nfa_comp_s *nfa_comp)
{
    static const char rname[] = "kiss_thin_nfa_calc_fail_states";

    // The root state has no fail state
    nfa_comp->root_state->fail_state = NULL;
    if (nfa_comp->anchored_root_state) {
        // The anchored root fails to the root
        nfa_comp->anchored_root_state->fail_state = nfa_comp->root_state;
    }

    thinnfa_debug(("%s: Calculating the fail states for all states\n", rname));

    // Iterate all transitions, and calculate fail states for the target states.
    // This would cover all states, except the initial (whose fail state was already set).
    // BFS order assures that a parent's fail state is already calculated when we reach the child.
    if (kiss_thin_nfa_iterate_trans_bfs(nfa_comp, kiss_thin_nfa_set_fail_state) != KISS_OK) {
        thinnfa_debug_err(("%s: Failed to calculate the fail states\n", rname));
        return KISS_ERROR;
    }

    // All states now have their fail states calculated
    ENUM_SET_FLAG(nfa_comp->flags, THIN_NFA_FAIL_STATES_CALCULATED);

    // Optimization - reduce fail states
    kiss_thin_nfa_reduce_fail_states(nfa_comp);

    return KISS_OK;
}


// Set a state's BNFA offset to the size so far, and increment by the state size.
static void
set_state_offset(kiss_thin_nfa_state_t *state, kiss_bnfa_offset_t *cur_offset)
{
    static const char rname[] = "set_state_offset";
    u_int state_size=0, match_size=0;

    verify_state(state->comp, state);

    if (state->bnfa_offset == KISS_BNFA_OFFSET_INVALID) {
        // Room for the actual state - negative offset for full states, positive for partial.
        if ((state->flags & THIN_NFA_STATE_FULL) && (*cur_offset<0)) {
            state_size = sizeof(kiss_bnfa_full_state_t);
        } else if (!(state->flags & THIN_NFA_STATE_FULL) && (*cur_offset>=0)) {
            state_size = kiss_bnfa_partial_state_size(state->num_trans);
        }
    }

    if (state->bnfa_incoming_off == KISS_BNFA_OFFSET_INVALID) {
        // Room for a match state - if needed, must be a positive offset.
        if ((state->flags & THIN_NFA_STATE_MATCH) && (*cur_offset >= 0)) {
            match_size = sizeof(kiss_bnfa_match_state_t);
            if (state->flags & THIN_NFA_STATE_FULL) {
                // Need a jump state too
                match_size += kiss_bnfa_partial_state_size(0);
            }
        }
    }

    // Update the state offsets
    if (match_size > 0) {
        thinnfa_debug_extended(("%s: State %s was given a match offset %d size %d", rname, state_name(state),
            *cur_offset, match_size));
        state->bnfa_incoming_off = *cur_offset;
        *cur_offset += match_size;
    }
    if (state_size > 0) {
        thinnfa_debug_extended(("%s: State %s was given a real offset %d size %d", rname, state_name(state),
            *cur_offset, state_size));
        state->bnfa_offset = *cur_offset;
        *cur_offset += state_size;
        if (!(state->flags & THIN_NFA_STATE_MATCH)) {
            // Incoming transitions go directly to the state
            state->bnfa_incoming_off = state->bnfa_offset;
        }
    }
}

// Check if compressed offset fits full state offset size
static BOOL
comp_offset_fits_short(kiss_bnfa_comp_offset_t comp_offset)
{
    if ((comp_offset) != (kiss_bnfa_short_offset_t)(comp_offset)) {
        return FALSE;
    }
    return TRUE;
}

// Mark all child of a given state as reacheable as reachable from full state
static void
kiss_bnfa_mark_childs_reach_from_full(kiss_thin_nfa_state_t *state)
{
    kiss_thin_nfa_state_t *child;

    for (child = state->child; child != NULL; child = child->sibling) {
        ENUM_SET_FLAG(child->flags, THIN_NFA_STATE_REACH_FROM_FULL);
    }
}

// Mark all states that are reachable from a given full state,
// in order to place them at lower offsets to avoid possible overflow due to offset compression.
// If a state`s fail state is of partial type, mark it`s children too
static void
kiss_bnfa_mark_reachable_from_full(kiss_thin_nfa_state_t *state) {

    kiss_bnfa_mark_childs_reach_from_full(state);
    for (state = state->fail_state; state && !(state->flags & THIN_NFA_STATE_FULL); state = state->fail_state) {
        kiss_bnfa_mark_childs_reach_from_full(state);
    }
}

// Calcultate the offset of each BNFA state, and the entire BNFA size.
// Sets nfa_comp->offset_list to an array, holding the BNFA offset for each state at [state_id].
// Sets *bnfa_size_p to the total BNFA size.
static kiss_ret_val
kiss_bnfa_calc_offsets(struct thin_nfa_comp_s *nfa_comp)
{
    static const char rname[] = "kiss_bnfa_calc_offsets";
    kiss_thin_nfa_state_t *state;
    kiss_bnfa_offset_t cur_offset;

    // Full states have negative offsets. So the first state's offset depends on the number of full states.
    cur_offset = -(kiss_bnfa_offset_t)(nfa_comp->full_state_num * sizeof(kiss_bnfa_full_state_t));
    nfa_comp->min_bnfa_off = cur_offset;

    // Put the anchored root state first, because it's the initial state
    if (nfa_comp->anchored_root_state) {
        KISS_ASSERT(nfa_comp->anchored_root_state->flags & THIN_NFA_STATE_FULL,
            "%s: The anchored root %s must be a full state\n", rname, state_name(nfa_comp->anchored_root_state));
        set_state_offset(nfa_comp->anchored_root_state, &cur_offset);
    }

    // If there's no anchored root, then root must be initial. If there is, validation expects it second.
    set_state_offset(nfa_comp->root_state, &cur_offset);

    // in this loop we add only the full states, which have negative offsets
    for (state = nfa_comp->root_state; state != NULL; state = kiss_thin_nfa_get_subsequent_state(nfa_comp, state)) {
        if (state->flags & THIN_NFA_STATE_FULL) {
            kiss_bnfa_mark_reachable_from_full(state);    // Mark child states so they'll get low offsets
            set_state_offset(state, &cur_offset);
        }
    }
    // We added all full states and moving to partials - we must be at offset 0.
    KISS_ASSERT(cur_offset==0,
        "%s: Offset %d != 0 after adding %d full states\n", rname, cur_offset, nfa_comp->full_state_num);

    // in this loop we add states that are reachable from full states. We want them at low offsets to avoid
    // possible overflow due to offset compression
    for (state = nfa_comp->root_state; state != NULL; state = kiss_thin_nfa_get_subsequent_state(nfa_comp, state)) {
        if (state->flags & THIN_NFA_STATE_REACH_FROM_FULL){
            set_state_offset(state, &cur_offset);
        }
    }

    // Make sure we have not exceede the limit of offsets that can be compressed to 16bit
    // Note: the test is a little too strict - we check the first state that is not reachable from a full state
    // instead of the last state that is reachable
    if (!comp_offset_fits_short(kiss_bnfa_offset_compress(cur_offset))) {
        thinnfa_debug_err(("%s: Current offset is %d, not reachable from the full state\n", rname, cur_offset));
        kiss_thin_nfa_set_comp_error(nfa_comp, "Exceeded the limit of reachable states");
        return KISS_ERROR;
    }

    // in this loop we add the partial and mathing states, which weren't handled in the loop above.
    for (state = nfa_comp->root_state; state != NULL; state = kiss_thin_nfa_get_subsequent_state(nfa_comp, state)) {
        set_state_offset(state, &cur_offset);
    }
    // The current offset is the size of partial states. Add the full state size to get the total size.
    nfa_comp->max_bnfa_off = cur_offset;

    thinnfa_debug_major(("%s: BNFA size - %u full states, %u partial states, total %u bytes\n", rname,
        nfa_comp->full_state_num,
        nfa_comp->state_num-nfa_comp->full_state_num,
        nfa_comp->max_bnfa_off - nfa_comp->min_bnfa_off));

    return KISS_OK;
}


// Get a state's BNFA offset.
// skip_match makes a difference for matching states:
//   TRUE  - Get the actual state, where the transition table is.
//   FALSE - Get the match state, where incoming transitions should go.
static kiss_bnfa_offset_t
state_bnfa_offset(kiss_thin_nfa_state_t *state, BOOL skip_match)
{
    return skip_match ? state->bnfa_offset : state->bnfa_incoming_off;
}


// Convert a BNFA offset to a BNFA state pointer
static kiss_bnfa_state_t *
comp_bnfa_offset_to_state(struct thin_nfa_comp_s *nfa_comp, kiss_bnfa_offset_t bnfa_offset)
{
    return kiss_bnfa_offset_to_state_write(nfa_comp->runtime_nfa->bnfa, bnfa_offset);
}


// Get a pointer to a state in the BNFA.
// skip_match makes a difference for matching states:
//   TRUE  - Get the actual state, where the transition table is.
//   FALSE - Get the match state, where incoming transitions should go.
static kiss_bnfa_state_t *
comp_to_bnfa_state(kiss_thin_nfa_state_t *state, BOOL skip_match)
{
    return comp_bnfa_offset_to_state(state->comp, state_bnfa_offset(state, skip_match));
}

// Move next to state_bnfa_offset. assert inside.
static kiss_bnfa_short_offset_t
state_bnfa_short_offset(kiss_thin_nfa_state_t *state)
{
    static const char rname[] = "state_bnfa_short_offset";
    kiss_bnfa_comp_offset_t comp_offset = kiss_bnfa_offset_compress(state_bnfa_offset(state, FALSE));

    KISS_ASSERT(comp_offset_fits_short(comp_offset),
        "%s: Compressed offset %d exceeds the allowed size\n", rname, comp_offset);

    return (kiss_bnfa_short_offset_t) comp_offset;
}


// If character translation is enabled, duplicate ch's transition to all equivalents
static void
add_equivalent_transitions(struct thin_nfa_comp_s *nfa_comp, kiss_bnfa_full_state_t *bnfa_state, u_char ch)
{
    static const char rname[] = "add_equivalent_transitions";
    u_char other_ch;
    u_int group_size;

    if (!nfa_comp->xlation_tab) return;

    // Go over all characters within the same group
    group_size = 0;
    for (other_ch = nfa_comp->xlation_tab->rev[ch]; other_ch != ch; other_ch = nfa_comp->xlation_tab->rev[other_ch]) {
        thinnfa_debug_extended(("%s: Setting translated transition by %02x - same as %02x\n", rname, other_ch, ch));

        bnfa_state->transitions[other_ch] = bnfa_state->transitions[ch];

        // Prevent looping in case the table is corrupt
        group_size++;
        KISS_ASSERT_CRASH(group_size <= KISS_PM_ALPHABET_SIZE,
            "%s: Too many characters to translate into %02x\n", rname, ch);
    }
}


// Add a transition to a full transition table.
// If there's a translation table, add trnasitions for all equivalent characters.
static void
add_full_transition(
    struct thin_nfa_comp_s *nfa_comp,
    kiss_bnfa_full_state_t *bnfa_state,
    kiss_thin_nfa_state_t *next_state
)
{
    static const char rname[] = "add_full_transition";
    u_char ch = next_state->tran_char;

    thinnfa_debug_extended(("%s: Setting the transition by %02x to %s\n", rname,
        next_state->tran_char, state_name(next_state)));

    // Set the transition, for ch and equivalent characters
    bnfa_state->transitions[ch] = state_bnfa_short_offset(next_state);
    add_equivalent_transitions(nfa_comp, bnfa_state, ch);
}

#if !defined(KERNEL)

// A recursive algorithm to build full state tables.
// Much faster than the previous algorithm, but shouldn't be used in the kernel.
// Allow mutual recursion between these two functions:
static void build_full_trans_table(kiss_thin_nfa_state_t *comp_state);
static void get_full_trans_table(kiss_thin_nfa_state_t *target_state, kiss_thin_nfa_state_t *source_state);


// Get the transition table of source_state and write it in target_state's.
// source_state is somewhere in the fail state chain of target_state.
static void
get_full_trans_table(kiss_thin_nfa_state_t *target_state, kiss_thin_nfa_state_t *source_state)
{
    kiss_thin_nfa_state_t *child;
    kiss_bnfa_state_t *target_bnfa = comp_to_bnfa_state(target_state, TRUE);

    if (source_state != target_state && (source_state->flags & THIN_NFA_STATE_FULL)) {
        // We've reached a full state - just copy its transition table (build it first, if needed)
        build_full_trans_table(source_state);
        bcopy(comp_to_bnfa_state(source_state, TRUE)->full.transitions,
            target_bnfa->full.transitions,
            sizeof(target_bnfa->full.transitions));
        return;
    }

    // Start with our fail state's state table
    if (source_state->fail_state) {
        get_full_trans_table(target_state, source_state->fail_state);
    } else {
        int i;
        kiss_bnfa_short_offset_t root_bnfa_comp_offset = state_bnfa_short_offset(source_state);

        // Reached the root - fill with transitions to root
        for (i=0; i<KISS_PM_ALPHABET_SIZE; i++) {
            target_bnfa->full.transitions[i] = root_bnfa_comp_offset;
        }
    }

    // Override transitions which exist in this state
    for (child = source_state->child; child != NULL; child = child->sibling) {
        add_full_transition(target_state->comp, &target_bnfa->full, child);
    }
}


// Recursive function for building a full state's state table.
// target_bnfa_state is the state who's table we're building.
// source_state changes when recursing over the tail state chain
static void
build_full_trans_table(kiss_thin_nfa_state_t *comp_state)
{
    if (comp_state->flags & THIN_NFA_STATE_BUILT_TABLE) return;

    get_full_trans_table(comp_state, comp_state);

    ENUM_SET_FLAG(comp_state->flags, THIN_NFA_STATE_BUILT_TABLE);
}

#endif // KERNEL

static CP_INLINE kiss_ret_val
verify_add_state(kiss_thin_nfa_state_t *comp_state, kiss_bnfa_state_t *bnfa_state, u_int state_size,
    const char *caller, const char *type)
{
    const KissThinNFA *nfa_h = comp_state->comp->runtime_nfa.get();
    kiss_bnfa_offset_t bnfa_offset = (char *)bnfa_state - (char *)(nfa_h->bnfa);
    u_int state_alignment = (bnfa_offset < 0) ? sizeof(kiss_bnfa_full_state_t) : KISS_BNFA_STATE_ALIGNMENT;

    if ((bnfa_offset < nfa_h->min_bnfa_offset) || (bnfa_offset+(int)state_size > nfa_h->max_bnfa_offset)) {
        thinnfa_debug_err(("%s: Cannot add the %s state %s at the offset %d:%d - out of range %d:%d\n", caller, type,
            state_name(comp_state),
            bnfa_offset, bnfa_offset+state_size,
            nfa_h->min_bnfa_offset, nfa_h->max_bnfa_offset));
        return KISS_ERROR;
    }

    if ((bnfa_offset % state_alignment) != 0) {
        thinnfa_debug_err((
            "%s: Cannot add the %s state %s at the offset %d:%d - not aligned on %d bytes\n",
            caller,
            type,
            state_name(comp_state),
            bnfa_offset,
            bnfa_offset + state_size,
            state_alignment
        ));
        return KISS_ERROR;
    }

    thinnfa_debug(("%s: Adding the %s state %s, offsets %d:%d\n", caller, type,
        state_name(comp_state),
        bnfa_offset, bnfa_offset+state_size));

    return KISS_OK;
}


// Old, non-recursive and slow version on build_full_trans_table.
static void
build_full_trans_table_no_recursion(kiss_thin_nfa_state_t *comp_state)
{
    static const char rname[] = "build_full_trans_table_no_recursion";
    struct thin_nfa_comp_s *nfa_comp = comp_state->comp;
    kiss_bnfa_state_t *bnfa_state = comp_to_bnfa_state(comp_state, TRUE);
    kiss_thin_nfa_state_t *child;
    u_int i;

    // Go over all characters. Maintain a pointer to the next transition in the list.
    // We rely on the list being sorted.
    // We could simply call kiss_thin_nfa_calc_transition for each character. But it would look up again and
    //  again in the current state.
    child = comp_state->child;
    for (i = 0; i < KISS_PM_ALPHABET_SIZE; i++) {
        u_char ch = (u_char)i;
        kiss_thin_nfa_state_t *next_state;

        // Check if it's a canonic character (e.g. lowercase when we're case insensitive)
        if (kiss_thin_nfa_xlate_char(nfa_comp, ch) != ch) {
            // We'll fill this in when we reach the canonic character.
            continue;
        }

        if (child != NULL && child->tran_char == ch) {
            // Use the explicit transition
            next_state = child;

            // Go forward in the transition table
            child = child->sibling;

            thinnfa_debug_extended(("%s: Setting the explicit transition by %02x to %s\n", rname,
                ch, state_name(next_state)));
        } else {
            // Note: if comp_state is the initial, we pass from_state=NULL.
            // This works as desired (returning the initial state).
            next_state = kiss_thin_nfa_calc_transition(nfa_comp, comp_state->fail_state, ch);

            thinnfa_debug_extended(("%s: Setting the fail-state transition by %02x to %s\n", rname,
                ch, state_name(next_state)));
        }

        // Set the transition for this character and equivalents
        bnfa_state->full.transitions[ch] = state_bnfa_short_offset(next_state);
        add_equivalent_transitions(nfa_comp, &bnfa_state->full, ch);
    }
    ENUM_SET_FLAG(comp_state->flags, THIN_NFA_STATE_BUILT_TABLE);
}


// Build a full state's transition table in the BNFA.
// Either uses the explicit transition, or calculates using fail states.
static kiss_ret_val
kiss_bnfa_build_full_state(kiss_thin_nfa_state_t *comp_state)
{
    static const char rname[] = "kiss_bnfa_build_full_state";
    kiss_bnfa_state_t *bnfa_state = comp_to_bnfa_state(comp_state, TRUE);

    if (verify_add_state(comp_state, bnfa_state, sizeof(kiss_bnfa_full_state_t), rname, "full") != KISS_OK) {
        return KISS_ERROR;
    }

#if !defined(KERNEL)
    if (comp_state->comp->flags & THIN_NFA_USE_RECURSIVE_COMPILE) {
        build_full_trans_table(comp_state);
        return KISS_OK;
    }
#endif // KERNEL

    build_full_trans_table_no_recursion(comp_state);

    return KISS_OK;
}


static void
kiss_bnfa_build_partial_state_header(
    kiss_bnfa_partial_state_t *bnfa_state,
    u_int trans_num,
    kiss_bnfa_offset_t fail_offset
)
{
    bnfa_state->type = KISS_BNFA_STATE_PARTIAL;
    bnfa_state->trans_num = trans_num;
    bnfa_state->fail_state_offset = kiss_bnfa_offset_compress(fail_offset);
}


// Build a partial state's transition table in the BNFA.
// Temporary encoding - sets the state ID instead of the BNFA offset (which is yet unknown).
static kiss_ret_val
kiss_bnfa_build_partial_state(kiss_thin_nfa_state_t *comp_state)
{
    static const char rname[] = "kiss_bnfa_build_partial_state";
    kiss_bnfa_state_t *bnfa_state = comp_to_bnfa_state(comp_state, TRUE);
    kiss_thin_nfa_state_t *child;
    u_int trans_num;

    if (verify_add_state(
            comp_state,
            bnfa_state,
            kiss_bnfa_partial_state_size(comp_state->num_trans),
            rname,
            "partial"
        ) != KISS_OK) {
        return KISS_ERROR;
    }

    // Fill in the transition number and fail state
    kiss_bnfa_build_partial_state_header(&bnfa_state->partial, comp_state->num_trans,
        state_bnfa_offset(comp_state->fail_state, TRUE));
    thinnfa_debug_extended(("%s: The fail state is %s\n", rname, state_name(comp_state->fail_state)));

    // Build a transition for each existing character
    trans_num = 0;
    for (child = comp_state->child; child != NULL; child = child->sibling) {
        thinnfa_debug_extended(("%s: Setting the transition by %02x to %s\n", rname,
            child->tran_char, state_name(child)));
        bnfa_state->partial.transitions[trans_num].tran_char = child->tran_char;
        bnfa_state->partial.transitions[trans_num].next_state_offset =
            kiss_bnfa_offset_compress(state_bnfa_offset(child, FALSE));
        trans_num++;
    }
    KISS_ASSERT(trans_num == comp_state->num_trans, "%s: State %s should have %d transitions, but it has %d",
        rname, state_name(comp_state), comp_state->num_trans, trans_num);
    ENUM_SET_FLAG(comp_state->flags, THIN_NFA_STATE_BUILT_TABLE);

    return KISS_OK;
}


// Build a match state.
static kiss_ret_val
kiss_bnfa_build_match_state(kiss_thin_nfa_state_t *comp_state, u_int match_id)
{
    static const char rname[] = "kiss_bnfa_build_match_state";
    kiss_bnfa_offset_t match_bnfa_offset = state_bnfa_offset(comp_state, FALSE);
    kiss_bnfa_state_t *match_state = comp_bnfa_offset_to_state(comp_state->comp, match_bnfa_offset);
    kiss_bnfa_offset_t following_state_offset, real_state_offset;

    if (verify_add_state(comp_state, match_state, sizeof(kiss_bnfa_match_state_t), rname, "match") != KISS_OK) {
        return KISS_ERROR;
    }

    // Fill in the match state
    match_state->match.type = KISS_BNFA_STATE_MATCH;
    match_state->match.unused = 0;
    match_state->match.match_id = match_id;

    // Add a jump state if the real state isn't directly following the match state (i.e. for full-matching states).
    real_state_offset = state_bnfa_offset(comp_state, TRUE);
    following_state_offset = match_bnfa_offset + sizeof(kiss_bnfa_match_state_t);
    if (following_state_offset != real_state_offset) {
        kiss_bnfa_state_t *jump_state = comp_bnfa_offset_to_state(comp_state->comp, following_state_offset);

        // Add a jump state (a 0-transition partial state) to the real state
        if (verify_add_state(comp_state, jump_state, kiss_bnfa_partial_state_size(0), rname, "jump") != KISS_OK) {
            return KISS_ERROR;
        }
        kiss_bnfa_build_partial_state_header(&jump_state->partial, 0, real_state_offset);
    }
    return KISS_OK;
}


// Encode a state in binary NFA form.
static kiss_ret_val
kiss_bnfa_add_state(kiss_thin_nfa_state_t *comp_state, u_int offset_in_pat_match_array)
{
    if (comp_state->flags & THIN_NFA_STATE_MATCH) {
        // Build a match state (a jump state too if needed)
        if (kiss_bnfa_build_match_state(comp_state, offset_in_pat_match_array) != KISS_OK) return KISS_ERROR;
    }

    // Add the state
    if (comp_state->flags & THIN_NFA_STATE_FULL) {
        if (kiss_bnfa_build_full_state(comp_state) != KISS_OK) return KISS_ERROR;
    } else {
        if (kiss_bnfa_build_partial_state(comp_state) != KISS_OK) return KISS_ERROR;
    }

    return KISS_OK;
}

static uintptr_t
pat_key_hash_func(const void *key, CP_MAYBE_UNUSED void *info)
{
    const kiss_thin_nfa_pattern_array_t *pat_arr = (const kiss_thin_nfa_pattern_array_t *)key;
    const char* buf = (const char *)key;
    const char *buf_end;
    uintptr_t val = 0;

    buf_end = buf + kiss_thin_nfa_pattern_array_size(pat_arr->n_patterns);

    for (    ; buf != buf_end; buf++) {
        val = ((val >> 3) ^ (val<<5)) + *buf;
    }
    return val;
}

static int
pat_key_cmp_func(const void *key1, const void *key2, CP_MAYBE_UNUSED void *info)
{
    const kiss_thin_nfa_pattern_array_t *pat1 = (const kiss_thin_nfa_pattern_array_t *)key1;
    const kiss_thin_nfa_pattern_array_t *pat2 = (const kiss_thin_nfa_pattern_array_t *)key2;

    if (pat1->n_patterns != pat2->n_patterns) {
        return 1; // No match
    }

    return memcmp(pat1, pat2, kiss_thin_nfa_pattern_array_size(pat1->n_patterns));
}

static u_int
pattern_list_len(const kiss_thin_nfa_pattern_list_t *pat_list)
{
    const kiss_thin_nfa_pattern_list_t *pat;
    u_int n = 0;
    for (pat = pat_list; pat != NULL; pat = pat->next) {
        n++;
    }
    return n;
}

static kiss_ret_val
kiss_bnfa_match_patterns_prepare(struct thin_nfa_comp_s *nfa_comp, KissThinNFA *nfa)
{
    static const char rname[] = "kiss_bnfa_match_patterns_prepare";
    kiss_thin_nfa_pattern_array_t *pat_arr;
    kiss_thin_nfa_state_t *comp_state;
    u_int total_size_for_patterns;

    total_size_for_patterns = 0;
    for (comp_state = nfa_comp->root_state;
        comp_state != NULL;
        comp_state = kiss_thin_nfa_get_subsequent_state(nfa_comp, comp_state)) {
        if (comp_state->flags & THIN_NFA_STATE_MATCH) {
            if (!comp_state->ids) {
                thinnfa_debug_critical((
                    "%s: State %s is finite, but its IDs are null\n",
                    rname,
                    state_name(comp_state)
                ));
                kiss_thin_nfa_set_comp_error(nfa_comp, "The state is finite, but its IDs are null");
                return KISS_ERROR;
            }
            total_size_for_patterns += kiss_thin_nfa_pattern_array_size(pattern_list_len(comp_state->ids));
        }
    }

    if (total_size_for_patterns == 0) {
        thinnfa_debug_critical(("%s: no finite states?!\n", rname));
        kiss_thin_nfa_set_comp_error(nfa_comp, "no finite states?!");
        return KISS_ERROR;
    }

    // We allocate according to maximum possible size.
    // We might reduce it at the end, if duplicates exist.
    thinnfa_debug(("%s: alocating %u bytes for a pattern array\n", rname, total_size_for_patterns));
    pat_arr = (kiss_thin_nfa_pattern_array_t *)kiss_pmglob_memory_kmalloc_ex(
        total_size_for_patterns,
        rname,
        FW_KMEM_SLEEP
    );
    if (!pat_arr) {
        thinnfa_debug_critical((
            "%s: failed to allocate %d bytes for a complete pattern array\n",
            rname,
            total_size_for_patterns
        ));
        kiss_thin_nfa_set_comp_error(nfa_comp, "Failed to allocate memory for a complete pattern array");
        return KISS_ERROR;
    }

    nfa->pattern_arrays = pat_arr;
    nfa->pattern_arrays_size = total_size_for_patterns;

    nfa_comp->patterns_hash = kiss_hash_create_with_ksleep(
        nfa->match_state_num,
        pat_key_hash_func,
        pat_key_cmp_func,
        NULL
    );
    if (!nfa_comp->patterns_hash) {
        thinnfa_debug((
            "%s: failed to create patterns hash table for %u finite states\n",
            rname,
            nfa->match_state_num
        ));
        kiss_thin_nfa_set_comp_error(nfa_comp, "Failed to create patterns hash table for finite states");
        return KISS_ERROR;
    }

    return KISS_OK;
}

static kiss_ret_val
kiss_bnfa_match_patterns_finalize(struct thin_nfa_comp_s *nfa_comp, KissThinNFA *nfa, u_int new_size)
{
    static const char rname[] = "kiss_bnfa_match_patterns_finalize";
    kiss_thin_nfa_pattern_array_t *new_pat_arr;

    // Compact the match patter array, if needed
    if (new_size == nfa->pattern_arrays_size) {
        thinnfa_debug(("%s: no size change - the pattern array size is %u bytes\n", rname, new_size));
        return KISS_OK;
    }

    if (new_size > nfa->pattern_arrays_size) {
        thinnfa_debug_critical((
            "%s: new pattern array size (%u) is greater than the current size (%u). This should not happen.\n",
            rname,
            new_size,
            nfa->pattern_arrays_size
        ));
        kiss_thin_nfa_set_comp_error(nfa_comp, "Failed to allocate a complete pattern array");
        return KISS_ERROR;
    }

    new_pat_arr = (kiss_thin_nfa_pattern_array_t *)kiss_pmglob_memory_kmalloc_ex(new_size, rname, FW_KMEM_SLEEP);
    if (!new_pat_arr) {
        thinnfa_debug_critical(("%s: failed to allocate %d bytes for a complete pattern array\n", rname, new_size));
        kiss_thin_nfa_set_comp_error(nfa_comp, "Failed to allocate a complete pattern array");
        return KISS_ERROR;
    }

    thinnfa_debug(("%s: reducing the size from %u to %u\n", rname, nfa->pattern_arrays_size, new_size));
    bcopy(nfa->pattern_arrays, new_pat_arr, new_size);
    kiss_pmglob_memory_kfree(nfa->pattern_arrays, nfa->pattern_arrays_size, rname);
    nfa->pattern_arrays = new_pat_arr;
    nfa->pattern_arrays_size = new_size;
    return KISS_OK;
}


static kiss_ret_val
kiss_bnfa_copy_pat_list(
    const KissThinNFA *nfa,
    kiss_hash_t patterns_hash,
    kiss_thin_nfa_state_t *comp_state,
    u_int *last_used_offset_in_pat_match_array,
    u_int *offset_for_cur_state)
{
    static const char rname[] = "kiss_bnfa_copy_pat_list";

    if (comp_state->flags & THIN_NFA_STATE_MATCH) {
        kiss_thin_nfa_pattern_list_t *pat_list_ent;
        kiss_thin_nfa_pattern_array_t *pat_arr;
        kiss_thin_nfa_pattern_array_t *cached_pat_arr;
        u_int pat_arr_size;
        u_int n_patterns;
        u_int i;

        n_patterns = pattern_list_len(comp_state->ids);
        pat_arr_size = kiss_thin_nfa_pattern_array_size(n_patterns);

        if ((*last_used_offset_in_pat_match_array + pat_arr_size) > nfa->pattern_arrays_size) {
            thinnfa_debug_critical(("%s: offset (%u) + required size (%u) exceeds the total array size (%u)\n",
                rname, *last_used_offset_in_pat_match_array, pat_arr_size, nfa->pattern_arrays_size));
            return KISS_ERROR;
        }

        pat_arr = kiss_thin_nfa_offset_to_pat_array_ptr(nfa, *last_used_offset_in_pat_match_array);
        pat_arr->n_patterns = n_patterns;
        for (i = 0, pat_list_ent = comp_state->ids; i < pat_arr->n_patterns; pat_list_ent = pat_list_ent->next, i++) {
            bcopy(&(pat_list_ent->pattern), &(pat_arr->pattern[i]), sizeof(pat_list_ent->pattern));
        }

        kiss_thin_nfa_free_pattern_ids(comp_state->ids);
        comp_state->ids = NULL; // Prevent release when the state is cleaned up

        cached_pat_arr = (kiss_thin_nfa_pattern_array_t *)kiss_hash_lookkey(patterns_hash, pat_arr);
        if (cached_pat_arr) {
            u_int cached_offset;
            cached_offset = kiss_thin_nfa_pat_array_ptr_to_offset(nfa, cached_pat_arr);
            // No need to move the last_used_offset
            *offset_for_cur_state = cached_offset;
            thinnfa_debug((
                "%s: returning cached offset of %u for the state ID %u. "
                "%u patterns %u bytes. The offset stays at %u.\n",
                rname,
                *offset_for_cur_state,
                comp_state->state_id,
                n_patterns, pat_arr_size,
                *last_used_offset_in_pat_match_array
            ));
        } else {
            *offset_for_cur_state = *last_used_offset_in_pat_match_array;
            if (!kiss_hash_insert(patterns_hash, pat_arr, NULL)) {
                thinnfa_debug(("%s: failed to insert a pattern into a hash (non-critical error)\n", rname));
            }
            *last_used_offset_in_pat_match_array += pat_arr_size;
            thinnfa_debug((
                "%s: returning the offset of %u for the state ID %u. %u patterns, %u bytes. The offset moved to %u.\n",
                rname,
                *offset_for_cur_state,
                comp_state->state_id,
                n_patterns, pat_arr_size,
                *last_used_offset_in_pat_match_array
            ));
        }
    }

    return KISS_OK;
}


static void
kiss_bnfa_update_state_depth(kiss_thin_nfa_state_t *comp_state)
{
    struct kiss_thin_nfa_depth_map_s *map = &comp_state->comp->runtime_nfa->depth_map;
    u_char depth = MIN(comp_state->depth, KISS_THIN_NFA_MAX_ENCODABLE_DEPTH);
    kiss_bnfa_offset_t off;

    // Update depth at the state's offset
    off = comp_state->bnfa_offset;
    map->offset0[kiss_bnfa_offset_compress(off)] = depth;

    // Matching state? Update at the match state offset too.
    off = comp_state->bnfa_incoming_off;
    if (off == comp_state->bnfa_offset) return;
    map->offset0[kiss_bnfa_offset_compress(off)] = depth;

    // Full-matching state? Update at the jump state offset too.
    off += sizeof(kiss_bnfa_match_state_t);
    if (off == comp_state->bnfa_offset) return;
    map->offset0[kiss_bnfa_offset_compress(off)] = depth;
}


// Based on thin_nfa_comp_s structure we have built, create a binary Thin NFA.
// Parameter:
//  nfa_comp - the NFA's compilation data structure.
//
// Performance notes:
//  This function takes most of the CPU time in the compilation process (in my tests, at least).
//  Within it, time is divided about equally between full and partial states.
//  Full states take about 40 times more time, but there are about 40 times more partial states.
//  Overall, compilation time isn't bad, but there are surely optimization options.
//  Idea - when constructing a full state, start by bcopy() of its fail state transitions. This would require
//    filling the states in BFS order, which isn't done today.
static kiss_ret_val
kiss_bnfa_fill_states(struct thin_nfa_comp_s *nfa_comp)
{
    static const char rname[] = "kiss_bnfa_fill_states";
    KissThinNFA *nfa = nfa_comp->runtime_nfa.get();
    kiss_thin_nfa_state_t *comp_state;
    u_int last_used_offset_in_pat_match_array = 0;

    thinnfa_debug(("%s: Filling BNFA %p size %d with %d states\n", rname,
        nfa->bnfa_start, nfa->max_bnfa_offset-nfa->min_bnfa_offset, nfa_comp->state_num));

    if (kiss_bnfa_match_patterns_prepare(nfa_comp, nfa) != KISS_OK) {
        return KISS_ERROR;
    }

    // Go over the states and build the BNFA representation
    for (comp_state = nfa_comp->root_state;
        comp_state != NULL;
        comp_state = kiss_thin_nfa_get_subsequent_state(nfa_comp, comp_state)) {
        u_int state_id = comp_state->state_id;
        u_int offset_for_cur_state = (u_int)-1;

        if (kiss_bnfa_copy_pat_list(
                nfa, nfa_comp->patterns_hash, comp_state,
                &last_used_offset_in_pat_match_array,
                &offset_for_cur_state
            ) != KISS_OK) {
            thinnfa_debug_critical((
                "%s: kiss_bnfa_copy_pat_list() failed for the state %s\n",
                rname,
                state_name(comp_state)
            ));
            kiss_thin_nfa_set_comp_error(nfa_comp, "kiss_bnfa_copy_pat_list() failed");
            return KISS_ERROR;
        }

        // Update the maximum pattern length (length = state depth)
        if (comp_state->depth > nfa->max_pat_len) {
            nfa->max_pat_len = comp_state->depth;
        }

        // Build the state
        if (kiss_bnfa_add_state(comp_state, offset_for_cur_state) != KISS_OK) {
            thinnfa_debug_critical(("%s: Failed to add the state %d\n", rname, state_id));
            return KISS_ERROR;
        }

        // Update the depth map
        kiss_bnfa_update_state_depth(comp_state);
    }

    if (kiss_bnfa_match_patterns_finalize(nfa_comp, nfa, last_used_offset_in_pat_match_array) != KISS_OK) {
        return KISS_ERROR;
    }

    return KISS_OK;
}


static void
kiss_thin_nfa_fill_stats(struct thin_nfa_comp_s *nfa_comp)
{
    struct kiss_thin_nfa_specific_stats_s *stats = &nfa_comp->runtime_nfa->stats.specific;

    stats->num_of_states = nfa_comp->state_num;
    stats->num_of_final_states = nfa_comp->match_state_num;
}


// Get the nfa_comp structure and build, according to it, the runtime Thin NFA structure.
static kiss_ret_val
kiss_thin_nfa_build_bnfa(struct thin_nfa_comp_s *nfa_comp, CP_MAYBE_UNUSED u_int compile_flags)
{
    static const char rname[] = "kiss_thin_nfa_build_bnfa";

    thinnfa_debug_major(("%s: Converting the compiled Thin NFA to the binary form\n", rname));

    // Get the list of all BNFA offsets
    if (kiss_bnfa_calc_offsets(nfa_comp) != KISS_OK) {
        thinnfa_debug_err(("%s: Error allocating the offset list\n", rname));
        kiss_thin_nfa_set_comp_error(nfa_comp, "Failed to allocate the offset list");
        return KISS_ERROR;
    }

    // Allocate the runtime Thin NFA structure
    nfa_comp->runtime_nfa = kiss_thin_nfa_create(
        nfa_comp->match_state_num,
        nfa_comp->min_bnfa_off,
        nfa_comp->max_bnfa_off
    );
    if (!nfa_comp->runtime_nfa) {
        thinnfa_debug_err(("%s: Error creating the NFA\n", rname));
        kiss_thin_nfa_set_comp_error(nfa_comp, "Failed to allocate BNFA");
        return KISS_ERROR;
    }

    if (nfa_comp->anchored_root_state) {
        ENUM_SET_FLAG(nfa_comp->runtime_nfa->flags, KISS_THIN_NFA_HAS_ANCHOR);
    }

    // Build the BNFA we'll use on runtime
    if (kiss_bnfa_fill_states(nfa_comp) != KISS_OK) {
        thinnfa_debug_err(("%s: kiss_bnfa_fill_states() failed\n", rname));
        return KISS_ERROR;
    }

    // Copy the character translation table
    if (nfa_comp->xlation_tab) {
        bcopy(
            nfa_comp->xlation_tab->tab,
            nfa_comp->runtime_nfa->xlation_tab,
            sizeof(nfa_comp->runtime_nfa->xlation_tab)
        );
        ENUM_SET_FLAG(nfa_comp->runtime_nfa->flags, KISS_THIN_NFA_USE_CHAR_XLATION);
    }

    kiss_thin_nfa_fill_stats(nfa_comp);

    thinnfa_debug_major(("%s: Created the binary Thin NFA %p\n", rname, nfa_comp->runtime_nfa.get()));
    return KISS_OK;
}

static void
kiss_thin_nfa_select_options(struct thin_nfa_comp_s *nfa_comp, CP_MAYBE_UNUSED u_int compile_flags)
{
    ENUM_SET_FLAG(nfa_comp->flags, THIN_NFA_ENABLE_ANCHOR_OPT);
    nfa_comp->full_state_tier_num = kiss_thin_nfa_full_tiers_num;
    ENUM_SET_FLAG(nfa_comp->flags, THIN_NFA_USE_RECURSIVE_COMPILE);
    return;
}


// Compiling the SM according to Aho-Corasick algorithm.
//
// The DFA has two types of states:
// 1. Full states - have a transition for each possible character.
// 2. Partial states - only have transitions for characters that take us forward in some string.
//   For all other characters, a "fail state" is defined, and the transition is what that state would have done.
//
// Paraemters:
// patterns - a set of string patterns which the resulting automaton would search for.
// compile_flags - flags with the KISS_PM_COMP_ prefix.
// error - output - on failure, would be set to indicate the reason.
// Retuns NULL on error, pointer to a newly allocated handle on success.
std::unique_ptr<KissThinNFA>
kiss_thin_nfa_compile(const std::list<kiss_pmglob_string_s> &patterns, u_int compile_flags, KissPMError *error)
{
    static const char rname[] = "kiss_thin_nfa_compile";
    struct thin_nfa_comp_s *nfa_comp = NULL;
    std::unique_ptr<KissThinNFA> nfa;

    thinnfa_debug_major(("%s: Compiling a Thin NFA, flags=%x\n", rname, compile_flags));

    // Creates a new kiss_thin_dfa_handle with initial state allocated
    nfa_comp = kiss_thin_nfa_comp_create(error);
    if (nfa_comp == NULL)    {
        thinnfa_debug_err(("%s: Failed to create a compile time structure\n", rname));
        kiss_pm_error_set_details(error, KISS_PM_ERROR_INTERNAL, "Failed to allocate the compilation information");
        goto finish;
    }

    // Enable some optimization flags as needed
    kiss_thin_nfa_select_options(nfa_comp, compile_flags);

    // Handle character translation - instead of converting to lowercase, build a translation
    // tabel and use it when adding patterns to the trie and building transition tables.
    if (kiss_thin_nfa_create_xlation_tab(nfa_comp, compile_flags) != KISS_OK) {
        thinnfa_debug_err(("%s: Function kiss_thin_nfa_create_xlation_tab() failed\n", rname));
        goto finish;
    }

    // Build a trie which contains all the pattern texts.
    for (auto &pattern : patterns) {
        // Adding each pattern to the the Thin NFA - Aho-Corasick first phase
        if (kiss_thin_nfa_add_pattern_to_trie(nfa_comp, &pattern) != KISS_OK) {
            thinnfa_debug_err(("%s: Function kiss_thin_nfa_add_pattern_to_trie() failed\n", rname));
            goto finish;
        }
    }

    // Calculate fail states for all NFA states
    if (kiss_thin_nfa_calc_fail_states(nfa_comp) != KISS_OK)    {
        thinnfa_debug_err(("%s: Function kiss_thin_nfa_calc_fail_states() failed\n", rname));
        goto finish;
    }

    // Convert the compilation data structure to the runtime structure
    if (kiss_thin_nfa_build_bnfa(nfa_comp, compile_flags) != KISS_OK)    {
        thinnfa_debug_err(("%s: Function kiss_thin_nfa_build_bnfa() failed\n", rname));
        goto finish;
    }

    if (!kiss_thin_nfa_is_valid(nfa_comp->runtime_nfa.get())) {
        thinnfa_debug_err(("%s: Function kiss_thin_nfa_is_valid() failed\n", rname));
        goto finish;
    }

    // Get the resulting NFA (set NULL to protect from free)
    nfa = std::move(nfa_comp->runtime_nfa);
    thinnfa_debug_major(("%s: Successfully compiled the Thin NFA %p\n", rname, nfa.get()));

finish:
    if (nfa_comp != NULL)    {
        // We destroy the compilation data structure, whether we succeed or fail.
        kiss_thin_nfa_comp_destroy(nfa_comp);
    }
    return nfa;
}
