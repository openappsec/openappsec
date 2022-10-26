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

#ifndef __kiss_thin_nfa_base_h__
#define __kiss_thin_nfa_base_h__

#include "general_adaptor.h"

// ****************************** OVERVIEW *******************************
//  Contians basic Thin NFA structure, used by kiss_pm and bolt (prescan)
// ***********************************************************************

#define KISS_THIN_NFA_ALPHABET_SIZE 256

// Binary representation of the Thin NFA.
// This is what's actually used during runtime.
//
// Offsets in the BNFA
// -------------------
// Offsets are signed 32-bit integers, specifying the distance in bytes from the "offset 0" point.
//
// Offset 0 isn't the BNFA start - there are negative offsets:
//   All full states are in negative offsets. This is the only way to know that a state is full.
//   All other states are in positive offsets.
//
// In full states, offsets are encoded in 16 bits.
// In partial states, offsets are encoded in 24 bits.
// Offsets are compressed:
//   Positive offsets are divided by 4. This is possible because all state sizes are a multiple of 4 bytes.
//   Negative offsets are divided by 512 (the size of a full state). This is possible because negative offsets
//     are only used for full states, so their offsets are a (negative) multiple of the state size.
//
// Structure of a BNFA state
// -------------------------
// 1. Full state:
//    a. No header. Identified by the fact that its BNFA offset is negative.
//    b. 256 transitions, 16bits each (uncompressed offsets).
// 2. Common header, to partial and match states:
//    a. State type                        - 2 bits.
// 3. Partial state:
//    a. State type                        - 2 bits.
//    b. Transition number                 - 6 bits.
//    c. Fail state offset (compresed)     - 24 bits.
//    d. Per transition:
//       1) Character                      - 8 bits
//       2) Next state offset (compressed) - 24 bits
// 4. Match state:
//    a. State type                        - 2 bits.
//    b. Unused                            - 6 bits.
//    c. Match ID                          - 24 bits.
//
// Examples:
//
// Partial state, 2 transitions - 'a'->100, 'b'->104, fail-> -3072
//       +----+---+-----+---+-----+---+-----+
// Bits: | 2  | 6 |  24 | 8 | 24  | 8 | 24  |
//       +----+---+-----+---+-----+---+-----+
// Data: | P  | 2 |  -3 | a | 25  | b | 26  |
//       +----+---+-----+---+-----+---+-----+
//
// Full state, 0x00->200, 0x01->204, 0xff->280
//       +-----+-----+      +-----+
// Bits: | 16  | 16  |      | 16  |
//       +-----+-----+ .... +-----+
// Data: | 50  | 51  |      | 70  |
//       +-----+-----+      +-----+


// Types for normal and compressed (see comment above) BNFA offsets

typedef int kiss_bnfa_offset_t;          // Offset in bytes
typedef int kiss_bnfa_comp_offset_t;     // Compressed offset
typedef short kiss_bnfa_short_offset_t;  // Compressed offset in 16bits (for full states)

#define KISS_BNFA_OFFSET_INVALID ((int)0x80000000)

// State types
typedef enum {
    KISS_BNFA_STATE_PARTIAL,
    KISS_BNFA_STATE_MATCH,
    KISS_BNFA_STATE_FULL,

    KISS_BNFA_STATE_TYPE_NUM
} kiss_bnfa_state_type_t;


// State structure

// Use some header bits for the state type
#define KISS_BNFA_STATE_TYPE_BITS 2

// The type must fit in KISS_BNFA_STATE_TYPE_BITS bits
KISS_ASSERT_COMPILE_TIME(KISS_BNFA_STATE_TYPE_NUM <= (1<<KISS_BNFA_STATE_TYPE_BITS));

// Transition - partial state implementation
struct kiss_bnfa_partial_transition_s {
    u_int tran_char:8;
    kiss_bnfa_comp_offset_t next_state_offset:24;
};

#define KISS_BNFA_NUM_TRANS_BITS (8-KISS_BNFA_STATE_TYPE_BITS)
#define KISS_BNFA_MAX_TRANS_NUM ((1<<KISS_BNFA_NUM_TRANS_BITS)-1)

// Header common to all state types (except full)
typedef struct {
    kiss_bnfa_state_type_t type:KISS_BNFA_STATE_TYPE_BITS;
    u_int pad:(32-KISS_BNFA_STATE_TYPE_BITS);
} kiss_bnfa_minimal_state_t;

// Partial state
typedef struct {
    kiss_bnfa_state_type_t type:KISS_BNFA_STATE_TYPE_BITS;
    u_int trans_num:KISS_BNFA_NUM_TRANS_BITS;
    kiss_bnfa_comp_offset_t fail_state_offset:24;
    struct kiss_bnfa_partial_transition_s transitions[1]; // Actual size is trans_num
} kiss_bnfa_partial_state_t;

// Match state
typedef struct {
    kiss_bnfa_state_type_t type:KISS_BNFA_STATE_TYPE_BITS;
    u_int unused:KISS_BNFA_NUM_TRANS_BITS;
    u_int match_id:24;
} kiss_bnfa_match_state_t;

// Full state
typedef struct {
    kiss_bnfa_short_offset_t transitions[KISS_THIN_NFA_ALPHABET_SIZE]; // BNFA offset per character
} kiss_bnfa_full_state_t;

// Any state
typedef union {
    kiss_bnfa_minimal_state_t    common;
    kiss_bnfa_partial_state_t    partial;
    kiss_bnfa_match_state_t        match;
    kiss_bnfa_full_state_t        full;
} kiss_bnfa_state_t;

// All states are aligned on this boundary
#define KISS_BNFA_STATE_ALIGNMENT sizeof(int)

// Compress a given offset when the state type is known. If the type is a cmpile-time constant, it's faster than
// kiss_bnfa_offset_compress since it should be optimized
static CP_INLINE kiss_bnfa_comp_offset_t
kiss_bnfa_offset_quick_compress(kiss_bnfa_offset_t off, kiss_bnfa_state_type_t type)
{
    if (type == KISS_BNFA_STATE_FULL) {
        return off / (int)sizeof(kiss_bnfa_full_state_t);
    } else {
        return off / (int)KISS_BNFA_STATE_ALIGNMENT;
    }
}

// Decompress a given offset when the state type is known. If the type is a cmpile-time constant, it's faster than
// kiss_bnfa_offset_decompress since it should be optimized
static CP_INLINE kiss_bnfa_offset_t
kiss_bnfa_offset_quick_decompress(kiss_bnfa_comp_offset_t comp_off, kiss_bnfa_state_type_t type)
{
    if (type == KISS_BNFA_STATE_FULL) {
        return comp_off * (int)sizeof(kiss_bnfa_full_state_t);
    } else {
        return comp_off * (int)KISS_BNFA_STATE_ALIGNMENT;
    }
}

// Compress a BNFA offset, for use in partial states (24-bit encoding) and full states (16-bit encoding)
static CP_INLINE kiss_bnfa_comp_offset_t
kiss_bnfa_offset_compress(kiss_bnfa_offset_t off)
{
    return kiss_bnfa_offset_quick_compress(off, off < 0 ? KISS_BNFA_STATE_FULL : KISS_BNFA_STATE_PARTIAL);
}

// Decompress a BNFA offset, which was stored in a partial state (24-bit encoding) and full states (16-bit encoding)
static CP_INLINE kiss_bnfa_offset_t
kiss_bnfa_offset_decompress(kiss_bnfa_comp_offset_t off)
{
    return kiss_bnfa_offset_quick_decompress(off, off < 0 ? KISS_BNFA_STATE_FULL : KISS_BNFA_STATE_PARTIAL);
    }

// Get a state in the BNFA given its offset
static CP_INLINE const kiss_bnfa_state_t *
kiss_bnfa_offset_to_state(const kiss_bnfa_state_t *bnfa, kiss_bnfa_offset_t bnfa_offset)
{
    const char *bnfa_c = (const char *)bnfa;
    return (const kiss_bnfa_state_t *)(bnfa_c + bnfa_offset);
}

// Get a state in the BNFA given its offset - without const, usable for writing the state
static CP_INLINE kiss_bnfa_state_t *
kiss_bnfa_offset_to_state_write(kiss_bnfa_state_t *bnfa, kiss_bnfa_offset_t bnfa_offset)
{
    char *bnfa_c = (char *)bnfa;
    return (kiss_bnfa_state_t *)(bnfa_c + bnfa_offset);
}

// Get a state in the BNFA given its compressed offset
static CP_INLINE const kiss_bnfa_state_t *
kiss_bnfa_comp_offset_to_state(
    const kiss_bnfa_state_t *bnfa,
    kiss_bnfa_comp_offset_t bnfa_comp_offset,
    kiss_bnfa_state_type_t type
)
{
    return kiss_bnfa_offset_to_state(bnfa, kiss_bnfa_offset_quick_decompress(bnfa_comp_offset, type));
}

// Get the state type by its BNFA offset
static CP_INLINE kiss_bnfa_state_type_t
kiss_bnfa_state_type(const kiss_bnfa_state_t *bnfa, kiss_bnfa_comp_offset_t bnfa_comp_offset)
{
    if (bnfa_comp_offset < 0) return KISS_BNFA_STATE_FULL;
    return kiss_bnfa_comp_offset_to_state(bnfa, bnfa_comp_offset, KISS_BNFA_STATE_PARTIAL)->common.type;
}


// State size

// Get the size of a partial state with N transitions
static CP_INLINE u_int
kiss_bnfa_partial_state_size(u_int trans_num)
{
    // Header + transition table
    return KISS_OFFSETOF(kiss_bnfa_partial_state_t, transitions)
        + sizeof(struct kiss_bnfa_partial_transition_s) * (trans_num);
}

// Get the size of an existing state
static CP_INLINE u_int
kiss_bnfa_state_size(const kiss_bnfa_state_t *bnfa, kiss_bnfa_offset_t offset)
{
    switch (kiss_bnfa_state_type(bnfa, kiss_bnfa_offset_compress(offset))) {
        case KISS_BNFA_STATE_PARTIAL: {
            const kiss_bnfa_state_t *state = kiss_bnfa_offset_to_state(bnfa, offset);
            return kiss_bnfa_partial_state_size(state->partial.trans_num);
        }
        case KISS_BNFA_STATE_MATCH:        return sizeof(kiss_bnfa_match_state_t);
        case KISS_BNFA_STATE_FULL:        return sizeof(kiss_bnfa_full_state_t);

        case KISS_BNFA_STATE_TYPE_NUM: break;    // Can't happen
    }

    return 0;
}

// Flags for kiss_thin_nfa_s.flags and kiss_thin_nfa_prescan_hdr_s.flags
enum kiss_thin_nfa_flags_e {
    KISS_THIN_NFA_USE_CHAR_XLATION    = 0x01,      // Used for caseless and/or digitless
    KISS_THIN_NFA_HAS_ANCHOR        = 0x02,        // State at offset 0 is anchored root, not root
};


#endif // __kiss_thin_nfa_base_h__
