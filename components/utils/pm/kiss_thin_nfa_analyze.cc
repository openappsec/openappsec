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

#include <ctype.h>
#include "pm_adaptor.h"
#include "kiss_thin_nfa_impl.h"
#include "kiss_hash.h"

#define hash_t kiss_hash_t
#define hash_intcreate_ex(sz, kmem_flags) \
    kiss_hash_create(sz, (hkeyfunc_t)kiss_hash_intvalue, (hcmpfunc_t)kiss_hash_intcmp, NULL)
#define hash_lookup kiss_hash_lookup
#define hash_insert kiss_hash_insert
#define hash_find_hashent kiss_hash_find_hashent
#define hashent kiss_hashent
#define hash_iterator_create kiss_hash_iterator_create
#define hash_iterator_get_hashent kiss_hash_iterator_get_hashent
#define hash_iterator kiss_hash_iterator
#define hash_iterator_next_ent kiss_hash_iterator_next_ent
#define hash_iterator_destroy kiss_hash_iterator_destroy
#define hash_destroy kiss_hash_destroy

// Thin NFA validation code
// ------------------------
// We validate the following things:
// 1. For each state:
//    a. That it's within the BNFA bounds.
//    b. If matching, the pattern offset is valid.
// 2. For each transition:
//    a. That it points to a valid state.
//    b. For partial states, that the normal transitions point down the tree, and fail states point up.
// 3. For the entire tree, that all states are in it.
// 4. The pattern array is valid, and all offsets are used at least once.
typedef enum {
    VALIDATION_STAT_FLAG_NONE = 0x00,
    VALIDATION_STATE_IS_JUMP = 0x01,
    VALIDATION_STATE_IS_ANCHORED = 0x02,
    VALIDATION_STATE_BNFA_ONLY = 0x04,        // Match/jump states, not a real part of the tree
} validation_state_flags_t;


// Information we keep about a state while validating the Thin NFA
struct state_validation_data_s {
    kiss_bnfa_offset_t bnfa_offset;
    int level;
    struct state_validation_data_s *next;
    struct state_validation_data_s *parent_state;    // First arrived here from this state
    u_char trans_char;                               // First arrived here by transition using this character
    kiss_bnfa_state_type_t type;
    validation_state_flags_t flags;
    struct thinnfa_validation_status_s *validation;  // The global validation data
};


// In which direction do we expect a transition to be?
typedef enum {
    TRANS_DIRECTION_BACK,      // Fail state - must be a lower tier
    TRANS_DIRECTION_FAIL_ONLY, // Fail state of a state with not transition - leaf or jump state
    TRANS_DIRECTION_FORWARD,   // Partial state transition - must be a higher tier
    TRANS_DIRECTION_ANY        // Full state trnsition - we can't tell
} transition_direction_t;


struct thinnfa_validation_status_s {
    const KissThinNFA *nfa;                                 // The NFA being validated
    struct state_validation_data_s *state_data;             // Validation info per state
    struct state_validation_data_s *root, *anchored_root;   // Interesting special states
    u_int state_num;                                        // States we found in the automaton
    hash_t offset_to_data;                                  // BNFA offset -> &state_data[i]
    struct state_validation_data_s *q_head, *q_tail;        // Queue for BFS scan
    hash_t pat_array_offset_ref_count;                      // Offset in the pattern array ->
                                                            //     number of finite states using it
};


// Callbacks for PM dump
typedef enum {
    THIN_NFA_DUMP_FLAGS_NONE      = 0x00,
    THIN_NFA_DUMP_SKIP_ROOT_TRANS = 0x01,
} thin_nfa_dump_flags_t;

// Callbacks provided by different dump formats
typedef struct {
    void (*start_cb)        (const struct thinnfa_validation_status_s *validation);
    void (*state_start_cb)    (const struct state_validation_data_s *state_data);
    void (*transition_cb)  (const struct state_validation_data_s *from_state,
                            u_char tran_char,
                            kiss_bnfa_offset_t next_state_off);
    void (*state_end_cb)    (const struct state_validation_data_s *state_data);
    void (*end_cb)            (const struct thinnfa_validation_status_s *validation);
    thin_nfa_dump_flags_t     flags;
} thin_nfa_dump_cbs_t;

// Change name printing to compensate for annoying Wiki behavior with backslashes:
// "\\\x" is printed as "\x".
// There's no safe way to print a single backslash: "\\" is nothing, "\\\\" is "\\".
//  You can try "\\\", which works, unless it's at the end of the string.
static int doing_wiki_dump = 0;

// Change name printing to avoid various chars which confuse Excel in CSVs
static int doing_csv_dump = 0;

static int
is_csv_printable(u_char c)
{
    return !( c == '\\' || c == ',' || c == '\'' || c=='"' || c=='=' || c==' ' || c=='+' || c=='-');
}


// Get a printable representation of a character, suitable for inclusion in double quotes.
static const char *
char_to_printable(u_char ch)
{
    static char buf[8];

    if (!isprint(ch) || ch==' ' || (doing_wiki_dump && ch=='\\') || (doing_csv_dump && !is_csv_printable(ch))) {
        // Print the hex value if not printable
        snprintf(buf, sizeof(buf), "%sx%02X", doing_wiki_dump ? "\\\\\\" : "\\", ch);
    } else if (ch == '"' || ch == '\\') {
        // Escape " and \ so they will behave nicely in a double-quoted string
        snprintf(buf, sizeof(buf), "\\%c", ch);
    } else {
        // Just print the character
        snprintf(buf, sizeof(buf), "%c", ch);
    }
    return buf;
}


static struct state_validation_data_s *
thin_nfa_validation_offset_to_state(struct thinnfa_validation_status_s *validation, kiss_bnfa_offset_t bnfa_offset)
{
    return (struct state_validation_data_s *)hash_lookup(validation->offset_to_data, (void *)(intptr_t)bnfa_offset);
}

#define NUM_NAME_BUFS 3
#define NAME_BUF_LEN 50

// Generate a nice printable name for the state
static const char *
state_name(const struct state_validation_data_s *state)
{
    struct thinnfa_validation_status_s *validation = state->validation;
    static char name_bufs[NAME_BUF_LEN][NUM_NAME_BUFS];
    static int cur_name_buf = 0;
    char *name_buf;
    char *p;
    const struct state_validation_data_s *tmp_state;

    // Special cases
    if (state == validation->root) return "ROOT";
    if (state == validation->anchored_root) return "^ROOT";

    // Follow transitions backwards, build the name
    name_buf = name_bufs[cur_name_buf];
    cur_name_buf = (cur_name_buf+1)%NUM_NAME_BUFS;
    p=&name_buf[NAME_BUF_LEN-1];
    *p = '\0';

    if (!doing_csv_dump && state->flags&VALIDATION_STATE_BNFA_ONLY) {
        // Mark matching and jump states with a suffix.
        p--;
        *p = (state->flags&VALIDATION_STATE_IS_JUMP) ? '#' : '*';
    }

    // Follow transitions backwards, build the name
    for (tmp_state=state; tmp_state!=validation->root; tmp_state=tmp_state->parent_state) {
        const char *ctext;
        if (tmp_state->parent_state == NULL) {
            // Possible if we haven't iterated all states yet. Just give the BNFA offset
            snprintf(name_buf, NAME_BUF_LEN, "STATE_%d", state->bnfa_offset);
            return name_buf;
        }

        if (tmp_state->parent_state->flags&VALIDATION_STATE_BNFA_ONLY) {
            // The characters are reported in real states only
            continue;
        }

        // Add the transition character to the name. Make sure not to add \0.
        ctext = char_to_printable(tmp_state->trans_char);
        if (p < name_buf+strlen(ctext)) break;
        p -= strlen(ctext);
        bcopy(ctext, p, strlen(ctext));
    }

    if (tmp_state != validation->root) {
        // Didn't go back to the root - add ? prefix
        if (p > name_buf) p--;
        *p = '?';
    }
    return p;
}


// Return a state's epsilon transition, or KISS_BNFA_OFFSET_INVALID if none.
static kiss_bnfa_offset_t
validation_state_epsilon_trans(const struct state_validation_data_s *state_data)
{
    switch (state_data->type) {
        case KISS_BNFA_STATE_PARTIAL: {
            const kiss_bnfa_state_t *state = kiss_bnfa_offset_to_state(state_data->validation->nfa->bnfa,
                state_data->bnfa_offset);
            return kiss_bnfa_offset_decompress(state->partial.fail_state_offset);
        }
        case KISS_BNFA_STATE_MATCH:
            return state_data->bnfa_offset + sizeof(kiss_bnfa_match_state_t);

        case KISS_BNFA_STATE_FULL:
        default:
            return KISS_BNFA_OFFSET_INVALID;
    }
}


// How many outgoing transitions do we have?
static u_int
validation_state_trans_num(const struct state_validation_data_s *state_data)
{
    switch (state_data->type) {
        case KISS_BNFA_STATE_FULL:        return KISS_PM_ALPHABET_SIZE;
        case KISS_BNFA_STATE_MATCH:        return 0;
        case KISS_BNFA_STATE_PARTIAL: {
            const kiss_bnfa_state_t *state = kiss_bnfa_offset_to_state(state_data->validation->nfa->bnfa,
                state_data->bnfa_offset);
            return state->partial.trans_num;
        }

        case KISS_BNFA_STATE_TYPE_NUM: return 0;
    }
    return 0;
}


static void
thin_nfa_validation_queue_enq(struct state_validation_data_s *item)
{
    struct thinnfa_validation_status_s *validation = item->validation;
    // Add at the tail. Set the existing tail (if any) or head (if not) to point to the new item.
    if (validation->q_tail != NULL) {
        validation->q_tail->next = item;
    } else {
        validation->q_head = item;
    }
    validation->q_tail = item;
    item->next = NULL;
}


static void
thin_nfa_validation_queue_enq_head(struct state_validation_data_s *item)
{
    struct thinnfa_validation_status_s *validation = item->validation;
    item->next = validation->q_head;
    validation->q_head = item;
    if (validation->q_tail==NULL) {
        validation->q_tail = item;
    }
}


static struct state_validation_data_s *
thin_nfa_validation_queue_deq(struct thinnfa_validation_status_s *validation)
{
    struct state_validation_data_s *item;

    // Remove from the head
    item = validation->q_head;
    if (!item) return NULL;

    validation->q_head = item->next;
    if (validation->q_head == NULL) {
        // Removed last
        validation->q_tail = NULL;
    }
    item->next = NULL;
    return item;
}


// Is a state within the BNFA boundaries?
static kiss_ret_val
thin_nfa_validate_offset_in_range(const KissThinNFA *nfa_handle, kiss_bnfa_offset_t bnfa_offset, u_int state_size,
    const char *caller, const char *msg)
{
    if ((bnfa_offset >= nfa_handle->min_bnfa_offset) && (bnfa_offset+(int)state_size <= nfa_handle->max_bnfa_offset)) {
        return KISS_OK;
    }
    thinnfa_debug_critical(("%s: State at BNFA offset %d %s %d - out of range (%d:%d)\n",
        caller, bnfa_offset,
        msg, state_size, nfa_handle->min_bnfa_offset, nfa_handle->max_bnfa_offset));
    return KISS_ERROR;
}


// Validate the state, which is at a given BNFA offset, is within the BNFA boundaries
static kiss_ret_val
thin_nfa_validate_state_in_range(const KissThinNFA *nfa_handle, kiss_bnfa_offset_t bnfa_offset, u_int *state_size_p)
{
    static const char rname[] = "thin_nfa_validate_state_in_range";
    u_int state_size;

    // See that the basic header fits, so we don't read outside the BNFA
    if (thin_nfa_validate_offset_in_range(nfa_handle, bnfa_offset, sizeof(kiss_bnfa_minimal_state_t),
            rname, "header") != KISS_OK) {
        return KISS_ERROR;
    }

    // Find the state's real size
    state_size = kiss_bnfa_state_size(nfa_handle->bnfa, bnfa_offset);

    // See that the whole state fits in
    if (thin_nfa_validate_offset_in_range(nfa_handle, bnfa_offset, state_size, rname, "size") != KISS_OK) {
        return KISS_ERROR;
    }

    *state_size_p = state_size;
    return KISS_OK;
}


// Find the root and anchored root states
static kiss_ret_val
thin_nfa_validation_find_root(struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_find_root";
    kiss_bnfa_offset_t init_offset = validation->nfa->min_bnfa_offset;
    struct state_validation_data_s *initial;

    initial = thin_nfa_validation_offset_to_state(validation, init_offset);
    if (!initial) {
        thinnfa_debug_critical(("%s: Initial state (offset %d) not found\n", rname, init_offset));
        return KISS_ERROR;
    }

    if (validation->nfa->flags & KISS_THIN_NFA_HAS_ANCHOR) {
        // The initial is the anchored root, the real root immediatey follows
        kiss_bnfa_offset_t root_offset = init_offset + sizeof(kiss_bnfa_full_state_t);
        struct state_validation_data_s *root = thin_nfa_validation_offset_to_state(validation, root_offset);
        if (!root) {
            thinnfa_debug_critical(("%s: Failed to find root (offset %u)\n", rname, root_offset));
            return KISS_ERROR;
        }
        validation->root = root;
        validation->anchored_root = initial;
    } else {
        // No anchored root, the root is initial
        validation->root = initial;
        validation->anchored_root = NULL;
    }

    thinnfa_debug(("%s: BNFA at %p, root %p anchored root %p\n", rname, validation->nfa->bnfa,
        validation->nfa->bnfa + validation->root->bnfa_offset,
        validation->anchored_root ? validation->nfa->bnfa + validation->anchored_root->bnfa_offset : NULL));

    return KISS_OK;
}


// Set validation->state_num (so we can allocate validation data)
static kiss_ret_val
thin_nfa_validation_count_states(struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_count_states";
    kiss_bnfa_offset_t bnfa_offset;

    bnfa_offset = validation->nfa->min_bnfa_offset;
    validation->state_num = 0;
    while (bnfa_offset < validation->nfa->max_bnfa_offset) {
        u_int state_size;
        if (thin_nfa_validate_state_in_range(validation->nfa, bnfa_offset, &state_size) != KISS_OK) return KISS_ERROR;
        validation->state_num++;
        bnfa_offset += state_size;
    }

    thinnfa_debug(("%s: Found %d states\n", rname, validation->state_num));

    return KISS_OK;
}


// Go over all states and fill in validation data structure.
// Doesn't fill in the level - saved for a later BFS iteration.
static kiss_ret_val
thin_nfa_validation_find_states(struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_find_states";
    u_int i;
    kiss_bnfa_offset_t bnfa_offset;
    u_int states_added = 0;

    thinnfa_debug(("%s: Validating %p\n", rname, validation->nfa));

    bnfa_offset = validation->nfa->min_bnfa_offset;
    for (i = 0; i < validation->state_num; i++) {
        struct state_validation_data_s *state_data;
        const kiss_bnfa_state_t *state;
        kiss_bnfa_state_type_t type;
        u_int state_size;
        u_int req_alignment;

        // See that the state fits in the BNFA
        if (thin_nfa_validate_state_in_range(validation->nfa, bnfa_offset, &state_size) != KISS_OK) return KISS_ERROR;
        type = kiss_bnfa_state_type(validation->nfa->bnfa, kiss_bnfa_offset_compress(bnfa_offset));
        state = kiss_bnfa_offset_to_state(validation->nfa->bnfa, bnfa_offset);

        thinnfa_debug_extended(("%s: State %u offset %d type %d size %d\n", rname, i, bnfa_offset, type, state_size));
        if (type == KISS_BNFA_STATE_MATCH) {
            thinnfa_debug_extended(("%s: pattern array offset %u\n", rname, state->match.match_id));
        }

        // Verify that the offset and type agree
        switch (type) {
            case KISS_BNFA_STATE_FULL:
                if (bnfa_offset >= 0) {
                    thinnfa_debug_critical(("%s: Full state at positive offset %d\n", rname, bnfa_offset));
                    return KISS_ERROR;
                }
                req_alignment = sizeof(kiss_bnfa_full_state_t);
                break;

            case KISS_BNFA_STATE_MATCH:
            case KISS_BNFA_STATE_PARTIAL:
                if (bnfa_offset < 0) {
                    // Can't really happen, because kiss_bnfa_state_type would return KISS_BNFA_STATE_FULL.
                    thinnfa_debug_critical(("%s: State type %d at negative offset %d\n", rname, type, bnfa_offset));
                    return KISS_ERROR;
                }
                req_alignment = KISS_BNFA_STATE_ALIGNMENT;
                break;

            default:
                thinnfa_debug_critical(("%s: Invalid state type at offset %d - %d\n", rname, bnfa_offset, type));
                return KISS_ERROR;
        }

        // Verify that the offset is properly aligned
        if ((bnfa_offset % req_alignment) != 0) {
            thinnfa_debug_critical(("%s: State offset %d - type %d but not on %d boundary\n", rname,
                bnfa_offset, type, req_alignment));
            return KISS_ERROR;
        }

        // OK - remember the state and advance the offset
        state_data = &validation->state_data[states_added];
        states_added++;

        state_data->bnfa_offset = bnfa_offset;
        state_data->next = NULL;
        state_data->level = -1;            // Indicating not visited. We'll calculate it during BFS traversal.
        state_data->parent_state = NULL;    // No parent, yet (will stay this way for the root)
        state_data->trans_char = '\0';    // Meaningless when there's no parent_state
        state_data->type = type;
        state_data->flags = VALIDATION_STAT_FLAG_NONE;
        state_data->validation = validation;

        if (type == KISS_BNFA_STATE_MATCH) {
            ENUM_SET_FLAG(state_data->flags, VALIDATION_STATE_BNFA_ONLY);
        }

        if (hash_insert(validation->offset_to_data, (void *)(intptr_t)bnfa_offset, state_data) == 0) {
            // XXX: Failing verification on memory allocation error. Not nice.
            // Can first build the hash, without any verifications, and only then verify.
            thinnfa_debug_critical(("%s: validation hash insert %d->%p failed\n", rname, bnfa_offset, state_data));
            return KISS_ERROR;
        }
        bnfa_offset += state_size;
    }

    if (bnfa_offset != validation->nfa->max_bnfa_offset) {
        thinnfa_debug_critical(("%s: Found %d of %d states, reached offset %d, not %d\n", rname,
            states_added, validation->state_num, bnfa_offset, validation->nfa->max_bnfa_offset));
        return KISS_ERROR;
    }

    // Set pointers to root states
    if (thin_nfa_validation_find_root(validation) != KISS_OK) return KISS_ERROR;

    return KISS_OK;
}


// Follow a transition, by adding the next state to the scan list, if it wasn't added yet.
static void
thin_nfa_validation_add_next_state(
    struct state_validation_data_s *from_state_data,
    struct state_validation_data_s *next_state_data,
    u_char trans_char
)
{
    const KissThinNFA *nfa;
    int inc_level;

    if (next_state_data->level >= 0) {
        // We've already seen this state
        return;
    }

    if (from_state_data->flags&VALIDATION_STATE_BNFA_ONLY) {
        // A matching state and the following real state are on the same level.
        // Using the mathing state's incoming transition char makes the state name end up nice.
        inc_level = 0;
        trans_char = from_state_data->trans_char;
    } else {
        inc_level = 1;
    }

    if (from_state_data->flags & VALIDATION_STATE_IS_ANCHORED) {
        ENUM_SET_FLAG(next_state_data->flags, VALIDATION_STATE_IS_ANCHORED);
    }

    nfa = from_state_data->validation->nfa;
    if (nfa->flags & KISS_THIN_NFA_USE_CHAR_XLATION) {
        // Use the canonic character. Without it, states pointed from partial state get the lowercase char,
        // but states pointed from full states get the uppercase (because it's first)
        trans_char = nfa->xlation_tab[trans_char];
    }

    // Calculate the level and enqueue
    next_state_data->level = from_state_data->level + inc_level;
    next_state_data->parent_state = from_state_data;
    next_state_data->trans_char = trans_char;
    if (inc_level) {
        thin_nfa_validation_queue_enq(next_state_data);
    } else {
        //We want this one to be scanned immediately.
        thin_nfa_validation_queue_enq_head(next_state_data);
    }
}


// Check that a character's transition is to a valid state.
// Returns the next state's data, or NULL if invalid.
static kiss_ret_val
thin_nfa_validation_add_transition(struct state_validation_data_s *prev_state_data,
    u_int trans_char, kiss_bnfa_offset_t next_state_offset, transition_direction_t expected_dir)
{
    static const char rname[] = "thin_nfa_validation_add_transition";
    struct state_validation_data_s *next_state_data;
    const char *err_msg = NULL;

    // See that there's a state at the target offset
    next_state_data = thin_nfa_validation_offset_to_state(prev_state_data->validation, next_state_offset);
    if (!next_state_data) {
        thinnfa_debug_critical((
            "%s: Transition from '%s' by %02x expected direction %d -> BNFA offset %d - no such state",
            rname,
            state_name(prev_state_data), trans_char, expected_dir, next_state_offset
        ));
        return KISS_ERROR;
    }

    // Check that transitions are in the direction we expect
    switch (expected_dir) {
        case TRANS_DIRECTION_FORWARD:
            // Partial state explicit transition - must point to a state we've never seen before
            if (next_state_data->level >= 0) {
                err_msg = "must be a new fail state";
            }
            break;

        case TRANS_DIRECTION_BACK:
            // Fail state transition - must point to a state we've already seen, on a lower level
            if (next_state_data->level < 0) {
                err_msg = "transition to an unknown state";
            } else if (next_state_data->level >= prev_state_data->level) {
                err_msg = "transition to a higher level";
            } else if (next_state_data->type == KISS_BNFA_STATE_MATCH) {
                err_msg = "transition to match the state";
            }
            break;

        case TRANS_DIRECTION_FAIL_ONLY:
            // Fail state of a state with no transitions. Can be either:
            // Leaf state - we expect a transition to a known lower-level state.
            // Jump state - we expect a transition to a new full state.
            if (next_state_data->level < 0) {
                // Jump state. Remember this, so we won't increment the next state's level
                ENUM_SET_FLAG(prev_state_data->flags, VALIDATION_STATE_IS_JUMP);
                ENUM_SET_FLAG(prev_state_data->flags, VALIDATION_STATE_BNFA_ONLY);
                if (next_state_offset >= 0) {
                    // Jump states are meant to jump to full states.
                    err_msg = "Jump state to partial";
                }
            } else {
                // Leaf state
                if (next_state_data->level >= prev_state_data->level) {
                    // A state's fail state must be at a lower level
                    err_msg = "transition to a level higher than the leaf state";
                }
            }
            if (err_msg==NULL && next_state_data->type == KISS_BNFA_STATE_MATCH) {
                err_msg = "transition to match the leaf state";
            }
            break;

        case TRANS_DIRECTION_ANY:
            // Full state transition - can point anywhere
            break;
    }

    if (err_msg != NULL) {
        thinnfa_debug_critical((
            "%s: Transition from '%s' by %02x expected dir %d -> '%s', levels %d -> %d, %s\n",
            rname,
            state_name(prev_state_data),
            trans_char,
            expected_dir,
            state_name(next_state_data),
            prev_state_data->level,
            next_state_data->level,
            err_msg
        ));
        return KISS_ERROR;
    }

    // Add the next state to the tree
    thin_nfa_validation_add_next_state(prev_state_data, next_state_data, (u_char)trans_char);

    return KISS_OK;
}


// Do a BFS scan of the tree and check transitions
static kiss_ret_val
thin_nfa_validation_scan_tree(struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_scan_tree";
    kiss_ret_val ret;

    // Initialize scan list with the root. The list contains all states, whose level
    // was already calculated, but whose children were not examined yet.
    validation->q_head = validation->q_tail = NULL;
    validation->root->level = 0;
    thin_nfa_validation_queue_enq(validation->root);

    if (validation->anchored_root) {
        // ^ROOT behaves like ROOT's child, setting level 1 makes fail transitions to normal tree OK
        validation->anchored_root->level = 1;
        validation->anchored_root->parent_state = validation->root;
        validation->anchored_root->trans_char = '^';        // Makes printing the name nice
        ENUM_SET_FLAG(validation->anchored_root->flags, VALIDATION_STATE_IS_ANCHORED);
        thin_nfa_validation_queue_enq(validation->anchored_root);
    }

    // No errors yet
    ret = KISS_OK;

    while (1) {
        struct state_validation_data_s *state_data;
        const kiss_bnfa_state_t *state;

        // Remove an element from the list
        state_data = thin_nfa_validation_queue_deq(validation);
        if (!state_data) break;

        state = kiss_bnfa_offset_to_state(validation->nfa->bnfa, state_data->bnfa_offset);

        switch (state_data->type) {
            case KISS_BNFA_STATE_PARTIAL: {
                // Partial State
                const kiss_bnfa_partial_state_t *p_state = &state->partial;
                u_int i;

                // Check the fail state (tran_char=0 is because its meaningless)
                if (thin_nfa_validation_add_transition(state_data, 0, validation_state_epsilon_trans(state_data),
                        p_state->trans_num==0 ? TRANS_DIRECTION_FAIL_ONLY : TRANS_DIRECTION_BACK) != KISS_OK) {
                    ret = KISS_ERROR;
                }

                // Go over the transitions to all included characters
                for (i=0; i<p_state->trans_num; i++) {
                    // Verify that the transition list is sorted.
                    // Actually, we removed binary search so it no longer matters.
                    if (i>0 && (p_state->transitions[i].tran_char <= p_state->transitions[i-1].tran_char)) {
                        thinnfa_debug_critical((
                            "%s: Transitions from state %s not sorted - %02x after %02x\n",
                            rname,
                            state_name(state_data),
                            p_state->transitions[i].tran_char,
                            p_state->transitions[i-1].tran_char
                        ));
                        ret = KISS_ERROR;
                    }

                    // Verify that the transition points to a valid offset
                    if (thin_nfa_validation_add_transition(state_data, p_state->transitions[i].tran_char,
                            kiss_bnfa_offset_decompress(p_state->transitions[i].next_state_offset),
                            TRANS_DIRECTION_FORWARD) != KISS_OK) {
                        ret = KISS_ERROR;
                    }
                }

                break;
            }

            case KISS_BNFA_STATE_FULL: {
                // Full state
                u_int i;

                // Go over the transitions to all characters
                for (i=0; i<KISS_PM_ALPHABET_SIZE; i++) {
                    if (thin_nfa_validation_add_transition(state_data, i,
                            kiss_bnfa_offset_decompress(state->full.transitions[i]), TRANS_DIRECTION_ANY) != KISS_OK) {
                        ret = KISS_ERROR;
                    }
                }
                break;
            }

            case KISS_BNFA_STATE_MATCH:
                // Add an implicit transition to the next state
                if (thin_nfa_validation_add_transition(state_data, 0,
                        validation_state_epsilon_trans(state_data), TRANS_DIRECTION_FORWARD) != KISS_OK) {
                    ret = KISS_ERROR;
                }
                break;

            default:
                // Can't really happen - checked already in thin_nfa_validation_find_states.
                thinnfa_debug_critical((
                    "%s: State %s has invalid type %d\n",
                    rname,
                    state_name(state_data),
                    state_data->type
                ));
                ret = KISS_ERROR;
                break;
        }
    }

    return ret;
}


// See if there are states in the BNFA which were never visited
kiss_ret_val
thin_nfa_validation_unvisited_states(struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_unvisited_states";
    u_int i;
    kiss_ret_val ret = KISS_OK;

    for (i=0; i<validation->state_num; i++) {
        struct state_validation_data_s *state_data = &validation->state_data[i];
        if (state_data->level < 0) {
            thinnfa_debug_critical(("%s: State %s never visited\n", rname, state_name(state_data)));
            ret = KISS_ERROR;
        }
    }
    return ret;
}


// Verify that pattern arrays buffer is self-consistant, and insert offsets into hash
static kiss_ret_val
thin_nfa_validation_check_pattern_arrays(struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_check_pattern_arrays";
    u_int pat_arr_offset;

    if (!validation->nfa->pattern_arrays || !validation->nfa->pattern_arrays_size) {
        thinnfa_debug_critical(("%s: NULL pattern array (%p) or 0 length (%u)\n", rname,
            validation->nfa->pattern_arrays, validation->nfa->pattern_arrays_size));
        return KISS_ERROR;
    }

    pat_arr_offset = 0;
    while (pat_arr_offset < validation->nfa->pattern_arrays_size) {
        const kiss_thin_nfa_pattern_array_t *pat_arr;
        if (!hash_insert(validation->pat_array_offset_ref_count, (void *)(intptr_t)pat_arr_offset, (void *)0)) {
            thinnfa_debug_critical(("%s: failed to insert value into hash\n", rname));
            return KISS_ERROR;
        }
        pat_arr = kiss_thin_nfa_offset_to_pat_array_ptr(validation->nfa, pat_arr_offset);
        if (pat_arr->n_patterns == 0) {
            thinnfa_debug_critical((
                "%s: encounterd a pat array with 0 pattern at offset %u\n",
                rname,
                pat_arr_offset
            ));
            return KISS_ERROR;
        }
        pat_arr_offset += kiss_thin_nfa_pattern_array_size(pat_arr->n_patterns);
    }

    if (pat_arr_offset != validation->nfa->pattern_arrays_size) {
        thinnfa_debug_critical(("%s: pat_arr_offset (%u) is past total size (%u)\n", rname,
            pat_arr_offset, validation->nfa->pattern_arrays_size));
        return KISS_ERROR;
    }

    return KISS_OK;
}


// Verify that all match states point to a valid offset and increase ref count
static kiss_ret_val
thin_nfa_validation_check_match_states(const struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_check_match_states";
    kiss_ret_val ret = KISS_OK;
    u_int i;

    for (i=0; i < validation->state_num; i++) {
        struct state_validation_data_s *state_data = &validation->state_data[i];
        const kiss_bnfa_state_t *state;
        u_int pat_arr_offset;
        struct hashent **he;

        if (state_data->type != KISS_BNFA_STATE_MATCH) continue;

        state = kiss_bnfa_offset_to_state(validation->nfa->bnfa, state_data->bnfa_offset);
        pat_arr_offset = state->match.match_id;
        thinnfa_debug_extended(("%s: Found matching state %s pattern offset %u\n", rname,
            state_name(state_data), pat_arr_offset));

        he = hash_find_hashent(validation->pat_array_offset_ref_count, (void *)(intptr_t)pat_arr_offset);
        if (he && *he) {
            u_int *ref_count = (u_int *)(&((*he)->val));
            (*ref_count)++;
        } else {
            thinnfa_debug_critical(("%s: pattern offset (%u) for state %s is not valid!\n", rname,
                pat_arr_offset, state_name(state_data)));
            ret = KISS_ERROR;
        }
    }

    return ret;
}

// Check that all offsets are used at least once.
static kiss_ret_val
thin_nfa_validation_unused_pat_offsets(const struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_unused_offsets";
    hash_iterator hi;
    kiss_ret_val ret = KISS_OK;

    hi = hash_iterator_create(validation->pat_array_offset_ref_count);
    if (!hi) {
        thinnfa_debug_critical(("%s: failed to create hash iterator\n", rname));
        return KISS_ERROR;
    }

    do {
        struct hashent* he = hash_iterator_get_hashent(hi);
        if (!he) {
            thinnfa_debug_critical(("%s: failed to get hash entry\n", rname));
            ret = KISS_ERROR;
            continue;
        }
        if ((u_int *)he->val == 0) {
            thinnfa_debug_critical(("%s: offset %p has 0 ref count\n", rname, (u_int *)he->key));
            ret = KISS_ERROR;
        }
        // We use hash_iterator_next_ent and not hash_iterator_next becuase we store int as value
        // and if the value is 0, hash_iterator_next will indidate that the iteration is over.
    } while (hash_iterator_next_ent(hi));

    hash_iterator_destroy(hi);

    return ret;
}

// Check that the state map is correct
static kiss_ret_val
thin_nfa_validation_depth_map(const struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_depth_map";
    u_int i;
    kiss_ret_val ret = KISS_OK;

    for (i=0; i < validation->state_num; i++) {
        struct state_validation_data_s *state_data = &validation->state_data[i];
        u_int map_depth = kiss_bnfa_offset_to_depth(
            validation->nfa,
            kiss_bnfa_offset_compress(state_data->bnfa_offset)
        );
        u_int validation_depth = state_data->level;

        if (state_data->flags & VALIDATION_STATE_IS_ANCHORED) {
            // Validation treats ^ROOT as level 1 (and its children as level 1 more than real).
            validation_depth--;
        }

        if (validation_depth == map_depth) continue;
        if (map_depth == validation->nfa->max_pat_len && validation_depth >= KISS_THIN_NFA_MAX_ENCODABLE_DEPTH) {
            // kiss_bnfa_offset_to_depth returns max_pat_len for level 255 and up.
            continue;
        }

        thinnfa_debug_critical(("%s: State %s found in depth %d, map says %d (flags %x)\n", rname,
            state_name(state_data), validation_depth, map_depth, state_data->flags));
        ret = KISS_ERROR;
    }

    return ret;
}


static void
thin_nfa_validation_fini(struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_fini";
    if (validation->state_data != NULL) {
        fw_kfree(validation->state_data, validation->state_num * sizeof(struct state_validation_data_s), rname);
        validation->state_data = NULL;
    }
    if (validation->offset_to_data != NULL) {
        hash_destroy(validation->offset_to_data);
        validation->offset_to_data = NULL;
    }
    if (validation->pat_array_offset_ref_count != NULL) {
        hash_destroy(validation->pat_array_offset_ref_count);
        validation->pat_array_offset_ref_count = NULL;
    }

    validation->nfa = NULL;
}


static kiss_ret_val
thin_nfa_validation_init(const KissThinNFA *nfa, struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "thin_nfa_validation_init";

    bzero(validation, sizeof(*validation));
    validation->nfa = nfa;

    if (thin_nfa_validation_count_states(validation) < 0) {
        thinnfa_debug_err(("%s: Failed to count states\n", rname));
        goto failure;
    }

    // Allocate data for state validation information
    validation->state_data = (struct state_validation_data_s *)fw_kmalloc_sleep(
        validation->state_num * sizeof(struct state_validation_data_s),
        rname
    );
    if (!validation->state_data) {
        thinnfa_debug_err(("%s: Failed to allocate %d state pointers\n", rname, validation->state_num));
        goto failure;
    }

    // Allocate BNFA offset -> validation data mapping
    validation->offset_to_data = hash_intcreate_ex(validation->state_num, FW_KMEM_SLEEP);
    if (!validation->offset_to_data) {
        thinnfa_debug_err((
            "%s: Failed to allocate hash table for validating %d states\n",
            rname,
            validation->state_num
        ));
        goto failure;
    }

    // Allocate pattern arrays offset -> ref count mapping
    validation->pat_array_offset_ref_count = hash_intcreate_ex(nfa->match_state_num, FW_KMEM_SLEEP);
    if (!validation->pat_array_offset_ref_count) {
        thinnfa_debug_err((
            "%s: Failed to allocate hash table for offsets - %u finite states\n",
            rname,
            nfa->match_state_num
        ));
        goto failure;
    }

    if (thin_nfa_validation_find_states(validation) != KISS_OK) {
        thinnfa_debug_err(("%s: Failed to fill NFA state info\n", rname));
        goto failure;
    }

    return KISS_OK;

failure:
    thin_nfa_validation_fini(validation);
    return KISS_ERROR;
}


BOOL
kiss_thin_nfa_is_valid(const KissThinNFA *nfa_h)
{
    static const char rname[] = "kiss_thin_nfa_is_valid";
    BOOL valid = FALSE;
    struct thinnfa_validation_status_s validation;

    // Allocate and initialize validation data
    if (thin_nfa_validation_init(nfa_h, &validation) != KISS_OK) {
        thinnfa_debug_err(("%s: Failed to initialize validation data\n", rname));

        // We can't validate, so we assume the Thin NFA is valid.
        valid = TRUE;
        goto finish;
    }

    // Do a BFS scan to verify relations,
    // see that all states are reached, verify that pattern offsets are used correctly.
    if (thin_nfa_validation_scan_tree(&validation) != KISS_OK)                goto finish;
    if (thin_nfa_validation_unvisited_states(&validation) != KISS_OK)        goto finish;
    if (thin_nfa_validation_check_pattern_arrays(&validation) != KISS_OK)    goto finish;
    if (thin_nfa_validation_check_match_states(&validation) != KISS_OK)        goto finish;
    if (thin_nfa_validation_unused_pat_offsets(&validation) != KISS_OK)        goto finish;
    if (thin_nfa_validation_depth_map(&validation) != KISS_OK)                goto finish;

    valid = TRUE;

finish:
    if (valid) {
        thinnfa_debug_major(("%s: Thin NFA %p validation succeeded\n", rname, nfa_h));
    } else {
        thinnfa_debug_critical(("%s: Thin NFA %p validation failed\n", rname, nfa_h));
    }
    thin_nfa_validation_fini(&validation);
    return valid;
}


// Thin NFA Dump code:
// From here, till the end of the file, the code is about dumping the automaton in different formats.
// CSV dump - For Excel
// XML dump - For the JFlap automaton visualisation applet.
// Wiki dump - For the Wiki {graph-from-table} plugin.
static int *xml_dump_level_positions;
static u_int xml_dump_level_positions_size;

static void
xml_dump_positions_init(const struct thinnfa_validation_status_s *validation)
{
    static const char rname[] = "xml_dump_positions_init";
    u_int i;

    // Allocate a level->position map
    xml_dump_level_positions_size = validation->nfa->max_pat_len;
    xml_dump_level_positions = (int *)fw_kmalloc(
        xml_dump_level_positions_size * sizeof(*xml_dump_level_positions),
        rname
    );
    if (!xml_dump_level_positions) {
        thinnfa_debug_critical((
            "%s: Failed to allocate positions array (%d entries)\n",
            rname,
            xml_dump_level_positions_size
        ));
        // All X positions will be 0.
        return;
    }

    for (i=0; i<xml_dump_level_positions_size; i++) {
        xml_dump_level_positions[i] = 0;
    }
}


static void
xml_dump_positions_fini(void)
{
    static const char rname[] = "xml_dump_positions_fini";
    if (!xml_dump_level_positions) return;
    fw_kfree(xml_dump_level_positions, xml_dump_level_positions_size * sizeof(*xml_dump_level_positions), rname);
    xml_dump_level_positions = NULL;
}


// Get the X,Y position for a state at level N. Increment the position for next time
static void
xml_dump_get_position(int level, int *x, int *y)
{
    if (level < 0) {
        level = 0;
    }

    if (!xml_dump_level_positions || (u_int)level >= xml_dump_level_positions_size) {
        *y = 0;
    } else {
        *y = xml_dump_level_positions[level];
        xml_dump_level_positions[level] += 100;
    }
    *x = level*100;
}


static void
xml_dump_print_header(const struct thinnfa_validation_status_s *validation)
{
    xml_dump_positions_init(validation);

    kdprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    kdprintf("<!--Created with JFLAP 6.0.--> ");
    kdprintf("<structure>\n");
    kdprintf("\t<type>fa</type>\n");
    kdprintf("\t<automaton>\n");
    kdprintf("\t\t<!--The list of states.-->\n");
}


static void
xml_dump_print_transition_ex(const struct state_validation_data_s *from_state,
    u_char tran_char, kiss_bnfa_offset_t next_state_off, BOOL is_epsilon)
{
    kdprintf("\t\t"        "<transition>\n");
    kdprintf("\t\t\t"        "<from>%d</from>\n", from_state->bnfa_offset);
    kdprintf("\t\t\t"        "<to>%d</to>\n", next_state_off);
    if (is_epsilon) {
        kdprintf("\t\t\t"    "<read/>\n");        // Epsilon
    } else {
        kdprintf("\t\t\t"    "<read>%s</read>\n", char_to_printable(tran_char));
    }
    kdprintf("\t\t"        "</transition>\n");
}


static void
xml_dump_print_state_start(const struct state_validation_data_s *state_data)
{
    const KissThinNFA *nfa = state_data->validation->nfa;
    int x, y;
    kiss_bnfa_offset_t epslion_trans;

    xml_dump_get_position(state_data->level, &x, &y);

    kdprintf("\t\t"        "<state id=\"%d\" name=\"%s\">\n",
        state_data->bnfa_offset, state_name(state_data));
    kdprintf("\t\t\t"        "<x>%d</x>\n", x);
    kdprintf("\t\t\t"        "<y>%d</y>\n", y);
    if (state_data->bnfa_offset == nfa->min_bnfa_offset) {
        kdprintf("\t\t\t"    "<initial/>\n");
    }
    if (state_data->type == KISS_BNFA_STATE_MATCH) {
        kdprintf("\t\t\t"    "<final/>\n");
    }
    kdprintf("\t\t"        "</state>\n");

    // Print an epsilon transition, if there is one
    epslion_trans = validation_state_epsilon_trans(state_data);
    if (epslion_trans != KISS_BNFA_OFFSET_INVALID) {
        xml_dump_print_transition_ex(state_data, '\0', epslion_trans, TRUE);
    }
}


static void
xml_dump_print_transition(const struct state_validation_data_s *from_state,
    u_char tran_char, kiss_bnfa_offset_t next_state_off)
{
    xml_dump_print_transition_ex(from_state, tran_char, next_state_off, FALSE);
}


static void
xml_dump_print_state_end(CP_MAYBE_UNUSED const struct state_validation_data_s *state_data)
{
    // Nothing to do
}

static void
xml_dump_print_trailer(CP_MAYBE_UNUSED const struct thinnfa_validation_status_s *validation)
{
    kdprintf("\t</automaton>\n");
    kdprintf("</structure>\n");

    xml_dump_positions_fini();
}

static thin_nfa_dump_cbs_t xml_dump_cbs = {
    xml_dump_print_header,
    xml_dump_print_state_start,
    xml_dump_print_transition,
    xml_dump_print_state_end,
    xml_dump_print_trailer,
    THIN_NFA_DUMP_SKIP_ROOT_TRANS
};

static void
wiki_dump_print_header(CP_MAYBE_UNUSED const struct thinnfa_validation_status_s *validation)
{
    // Start generating state names suitable for Wiki
    doing_wiki_dump = 1;

    // The graph-from-table plugin will display the table lines below as a graph
    kdprintf("{graph-from-table}\n");
}

static const char *
wiki_dump_state_color(const struct state_validation_data_s *state_data)
{
    if (state_data->bnfa_offset==state_data->validation->nfa->min_bnfa_offset) return "cyan";        // Initial
    switch (state_data->type) {
        case KISS_BNFA_STATE_FULL:            return "yellow";
        case KISS_BNFA_STATE_PARTIAL:        return "white";
        case KISS_BNFA_STATE_MATCH:            return "green";

        case KISS_BNFA_STATE_TYPE_NUM: break;
    }
    return "red";        // Shouldn't happen
}

static void
wiki_dump_print_state(const struct state_validation_data_s *state_data)
{
    kiss_bnfa_offset_t epsilon_trans;

    // Format: |from|to|trans attrs|from attrs|to attrs|
    // to, trans attrs, to attrs are omitted, so we only provide the state's attributes
    kdprintf("|%d| | |label=\"%s\",fillcolor=%s|\n",
        state_data->bnfa_offset,
        state_name(state_data),
        wiki_dump_state_color(state_data));

    // Print epsilon transition, if any
    epsilon_trans = validation_state_epsilon_trans(state_data);
    if (epsilon_trans != KISS_BNFA_OFFSET_INVALID) {
        // Format: |from|to|trans attrs|
        kdprintf("|%d|%d|color=red|\n", state_data->bnfa_offset, epsilon_trans);
    }
}


static void
wiki_dump_print_transition(const struct state_validation_data_s *from_state,
    u_char tran_char, kiss_bnfa_offset_t next_state_off)
{
    // Format: |from|to|trans attrs|
    kdprintf("|%d|%d|label=\"%s\"|\n", from_state->bnfa_offset, next_state_off, char_to_printable(tran_char));
}


static void
wiki_dump_print_state_end(CP_MAYBE_UNUSED const struct state_validation_data_s *state_data)
{
    // Nothing to do
}


static void
wiki_dump_print_trailer(CP_MAYBE_UNUSED const struct thinnfa_validation_status_s *validation)
{
    kdprintf("{graph-from-table}\n");
    doing_wiki_dump = 0;
}


static thin_nfa_dump_cbs_t wiki_dump_cbs = {
    wiki_dump_print_header,
    wiki_dump_print_state,
    wiki_dump_print_transition,
    wiki_dump_print_state_end,
    wiki_dump_print_trailer,
    THIN_NFA_DUMP_SKIP_ROOT_TRANS
};


#ifdef KERNEL
#define kdprintf_no_prefix kdprintf
#endif

static void
csv_dump_print_header(CP_MAYBE_UNUSED const struct thinnfa_validation_status_s *validation)
{
    u_int i;

    // Start generating state names suitable for CSV / Excel
    doing_csv_dump = 1;

    // The graph-from-table plugin will display the table lines below as a graph
    kdprintf("Tier 1 CSV Dump start\n");

    kdprintf_no_prefix(
        "state_offset,state_name,level,is_match,is_partial,num_of_transitions,match_id_offset,fail_state_offset"
    );
    for (i = 0; i < KISS_PM_ALPHABET_SIZE; i++) {
        u_char ch = (u_char)i;
        kdprintf_no_prefix(",");
        switch (ch) {
            // Some printable characters are problamtic in CSV files
            case '\\': kdprintf_no_prefix("bslash"); break;
            case ',':  kdprintf_no_prefix("comma");  break;
            case '\'': kdprintf_no_prefix("quote");  break;
            case '\"': kdprintf_no_prefix("dquote"); break;
            case ' ':  kdprintf_no_prefix("space");  break;
            default:
                if (isprint(ch)) {
                    kdprintf_no_prefix("%c", ch);
                } else {
                    kdprintf_no_prefix("0x%02X", ch);
                }
                break;
        }
    }
    kdprintf_no_prefix("\n");
}


// Used to detect characters without a transition
static u_int csv_dump_next_trans;

static void
csv_dump_print_state_start(const struct state_validation_data_s *state_data)
{
    const kiss_bnfa_state_t *bnfa = state_data->validation->nfa->bnfa;
    const kiss_bnfa_state_t *state = kiss_bnfa_offset_to_state(bnfa, state_data->bnfa_offset);
    kiss_bnfa_offset_t epsilon_trans = validation_state_epsilon_trans(state_data);

    // Basic data - state_offset,state_name,level,is_match,is_partial,
    //              num_of_transitions,match_id_offset,fail_state_offset
    kdprintf_no_prefix("%d,%s,%d,%u,%u,%u",
        state_data->bnfa_offset,
        state_name(state_data),
        state_data->level,
        (state_data->type==KISS_BNFA_STATE_MATCH),
        (state_data->type==KISS_BNFA_STATE_PARTIAL),
        validation_state_trans_num(state_data)
    );
    if (state_data->type == KISS_BNFA_STATE_MATCH) {
        kdprintf_no_prefix(",%d", state->match.match_id);
    } else {
        kdprintf_no_prefix(", ");
    }
    if (epsilon_trans != KISS_BNFA_OFFSET_INVALID) {
        kdprintf_no_prefix(",%d", epsilon_trans);
    } else {
        kdprintf_no_prefix(", ");
    }

    csv_dump_next_trans = '\0';
}


static void
csv_dump_print_transition(CP_MAYBE_UNUSED const struct state_validation_data_s *from_state,
    u_char tran_char, kiss_bnfa_offset_t next_state_off)
{
    // Print skipped characters
    while (csv_dump_next_trans < tran_char) {
        kdprintf_no_prefix(", ");
        csv_dump_next_trans++;
    }

    kdprintf_no_prefix(",%d", next_state_off);
    csv_dump_next_trans = tran_char + 1;
}


static void
csv_dump_print_state_end(CP_MAYBE_UNUSED const struct state_validation_data_s *state_data)
{
    // Print skipped characters at the tail
    while (csv_dump_next_trans < KISS_PM_ALPHABET_SIZE) {
        kdprintf_no_prefix(", ");
        csv_dump_next_trans++;
    }

    kdprintf_no_prefix("\n");
}


static void
csv_dump_print_trailer(CP_MAYBE_UNUSED const struct thinnfa_validation_status_s *validation)
{
    kdprintf("Tier 1 CSV Dump end\n");
    doing_csv_dump = 0;
}


static thin_nfa_dump_cbs_t csv_dump_cbs = {
    csv_dump_print_header,
    csv_dump_print_state_start,
    csv_dump_print_transition,
    csv_dump_print_state_end,
    csv_dump_print_trailer,
    THIN_NFA_DUMP_FLAGS_NONE
};


static void
thin_nfa_dump_state(
    const struct thinnfa_validation_status_s *validation,
    const struct state_validation_data_s *state_data,
    const thin_nfa_dump_cbs_t *dump_format_cbs
)
{
    static const char  rname[] = "thin_nfa_dump_state";
    const kiss_bnfa_state_t *state = kiss_bnfa_offset_to_state(validation->nfa->bnfa, state_data->bnfa_offset);
    const kiss_bnfa_offset_t root_offset = validation->root->bnfa_offset;
    u_int i, trans_num;

    // Print some stuff at the state start
    dump_format_cbs->state_start_cb(state_data);

    // Print the transition table
    trans_num = validation_state_trans_num(state_data);
    for (i = 0; i < trans_num; i++) {
        u_char tran_char;
        kiss_bnfa_offset_t tran_bnfa_offset;

        // Get the transition's character and next state
        switch (state_data->type) {
            case KISS_BNFA_STATE_PARTIAL:
                tran_char = state->partial.transitions[i].tran_char;
                tran_bnfa_offset = kiss_bnfa_offset_decompress(state->partial.transitions[i].next_state_offset);
                break;

            case KISS_BNFA_STATE_FULL:
                tran_char = (u_char)i;
                tran_bnfa_offset = kiss_bnfa_offset_decompress(state->full.transitions[i]);
                break;

            default:
                // KISS_BNFA_STATE_MATCH has no transitions
                thinnfa_debug_critical(("%s: Bad type %d\n", rname, state_data->type));
                return;
        }

        // Possibly skip root transitions
        if ((tran_bnfa_offset==root_offset) && (dump_format_cbs->flags & THIN_NFA_DUMP_SKIP_ROOT_TRANS)) continue;

        // Print the transition
        dump_format_cbs->transition_cb(state_data, tran_char, tran_bnfa_offset);
    }

    // Print some stuff at the state end
    dump_format_cbs->state_end_cb(state_data);
}

static kiss_ret_val
thin_nfa_dump(const KissThinNFA *nfa, const thin_nfa_dump_cbs_t *dump_format_cbs)
{
    static const char rname[] = "thin_nfa_dump";
    struct thinnfa_validation_status_s validation;
    u_int i;
    kiss_ret_val ret = KISS_ERROR;

    // We don't want to crash or loop if the Thin NFA is corrupt, so validate first
    if (thin_nfa_validation_init(nfa, &validation) != KISS_OK) {
        thinnfa_debug_critical(("%s: Failed to initialize validation data\n", rname));
        goto cleanup;
    }

    // Go over the tree and follow all transitions
    if (thin_nfa_validation_scan_tree(&validation) != KISS_OK) {
        thinnfa_debug_critical(("%s: Tree scan failed - the BNFA is corrupt\n", rname));
        // Continue despite failure. We'll end up with ugly state names.
    }

    // The graph-from-table plugin will display the table lines below as a graph
    dump_format_cbs->start_cb(&validation);

    // Go over states and print them
    for (i=0; i<validation.state_num; i++) {
        thin_nfa_dump_state(&validation, &validation.state_data[i], dump_format_cbs);
    }

    dump_format_cbs->end_cb(&validation);

    ret = KISS_OK;
cleanup:
    thin_nfa_validation_fini(&validation);
    return ret;
}


kiss_ret_val
kiss_thin_nfa_dump(const KissThinNFA *nfa, enum kiss_pm_dump_format_e format)
{
    static const char rname[] = "kiss_thin_nfa_dump";
    thin_nfa_dump_cbs_t *format_cbs = NULL;

    switch (format) {
        case KISS_PM_DUMP_XML:
            format_cbs = &xml_dump_cbs;
            break;
        case KISS_PM_DUMP_CSV:
            format_cbs = &csv_dump_cbs;
            break;
        case KISS_PM_DUMP_WIKI:
            format_cbs = &wiki_dump_cbs;
            break;
    }

    if (!format_cbs) {
        thinnfa_debug_critical(("%s: Invalid dump format %d\n", rname, format));
        return KISS_ERROR;
    }

    return thin_nfa_dump(nfa, format_cbs);
}
