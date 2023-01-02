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

// Thin NFA Construction and Destruction
// -------------------------------------
// This file contains code that builds a Thin NFA.
// The functions here may be called from compilation, serialization and de-serialization contexts.
// The code allows allocating and releasing the Thin NFA structure, as well as serializing and deserializing it.

#include "kiss_thin_nfa_impl.h"

// Allocate and fill in a pattern ID structure
kiss_ret_val
kiss_thin_nfa_add_pattern_id(kiss_thin_nfa_pattern_list_t **pat_list_p, const kiss_thin_nfa_pattern_t *new_pat)
{
    static const char rname[] = "kiss_thin_nfa_add_pattern_id";
    kiss_thin_nfa_pattern_list_t **pat_ptr;
    kiss_thin_nfa_pattern_list_t *pat;

    // Go over the pattern list - look for our pattern, and find the end
    for (pat_ptr = pat_list_p; *pat_ptr != NULL; pat_ptr = &((*pat_ptr)->next)) {
        kiss_thin_nfa_pattern_t *list_pat = &(*pat_ptr)->pattern;

        if (list_pat->id == new_pat->id) {
            // Already there - nothing to do
            thinnfa_debug((
                "%s: Pattern already exists - ID=%d flags=%x(%x) len=%d(%d)\n",
                rname,
                new_pat->id,
                new_pat->pattern_id_flags,
                list_pat->pattern_id_flags,
                new_pat->len,
                list_pat->len
            ));
            return KISS_OK;
        }
    }

    // Allocate the pattern structure
    pat = (kiss_thin_nfa_pattern_list_t *)kiss_pmglob_memory_kmalloc(sizeof(kiss_thin_nfa_pattern_list_t), rname);
    if (!pat) {
        thinnfa_debug_err(("%s: Failed to allocate pattern id\n", rname));
        return KISS_ERROR;
    }

    // Fill in the fields
    bcopy(new_pat, &pat->pattern, sizeof(pat->pattern));

    thinnfa_debug((
        "%s: Added pattern ID=%d flags=%x len=%d\n",
        rname,
        new_pat->id,
        new_pat->pattern_id_flags,
        new_pat->len
    ));

    // Add to the linked list of patternss.
    *pat_ptr = pat;
    pat->next = NULL;

    return KISS_OK;
}


// Free an entire list of pattern IDs.
void
kiss_thin_nfa_free_pattern_ids(kiss_thin_nfa_pattern_list_t *pat_list)
{
    static const char rname[] = "kiss_thin_nfa_free_pattern_ids";
    kiss_thin_nfa_pattern_list_t *pat, *next;

    for (pat = pat_list; pat != NULL; pat = next) {
        next = pat->next;
        thinnfa_debug((
            "%s: Releasing pattern ID=%d flags=%x len=%u\n",
            rname,
            pat->pattern.id,
            pat->pattern.pattern_id_flags,
            pat->pattern.len
        ));
        kiss_pmglob_memory_kfree(pat, sizeof(kiss_thin_nfa_pattern_list_t), rname);
    }
    return;
}


// Allocate and initialize statistics
static kiss_ret_val
kiss_thin_nfa_stats_init(kiss_thin_nfa_stats stats)
{

    if (kiss_pm_stats_common_init(&(stats->common)) != KISS_OK) {
        return KISS_ERROR;
    }

    bzero(&(stats->specific), sizeof(struct kiss_thin_nfa_specific_stats_s));

    return KISS_OK;
}


// Free statistics
static void
kiss_thin_nfa_stats_free(kiss_thin_nfa_stats stats)
{
    kiss_pm_stats_common_free(&(stats->common));
}


static kiss_ret_val
kiss_thin_nfa_alloc_depth_map(KissThinNFA *nfa)
{
    static const char rname[] = "kiss_thin_nfa_alloc_depth_map";
    kiss_bnfa_comp_offset_t min_comp_off, max_comp_off;

    // The depth map is addressed by the compressed offset
    min_comp_off = kiss_bnfa_offset_compress(nfa->min_bnfa_offset);
    max_comp_off = kiss_bnfa_offset_compress(nfa->max_bnfa_offset);

    nfa->depth_map.size = max_comp_off - min_comp_off;
    nfa->depth_map.mem_start = (u_char *)kiss_pmglob_memory_kmalloc_ex(nfa->depth_map.size, rname, FW_KMEM_SLEEP);
    if (!nfa->depth_map.mem_start) {
        thinnfa_debug_err((
            "%s: Error allocating the depth map, size %d (BNFA offsets %d:%d)\n",
            rname,
            nfa->depth_map.size,
            nfa->min_bnfa_offset,
            nfa->max_bnfa_offset
        ));
        return KISS_ERROR;
    }
    // Find the place for offset 0. min_comp_offset is negative, so it's after mem_start.
    nfa->depth_map.offset0 = nfa->depth_map.mem_start - min_comp_off;

    return KISS_OK;
}


static void
kiss_thin_nfa_destroy_depth_map(KissThinNFA *nfa)
{
    static const char rname[] = "kiss_thin_nfa_destroy_depth_map";
    if (nfa->depth_map.mem_start != NULL) {
        kiss_pmglob_memory_kfree(nfa->depth_map.mem_start, nfa->depth_map.size, rname);
        nfa->depth_map.mem_start = NULL;
        nfa->depth_map.offset0 = NULL;
    }
}


KissThinNFA::~KissThinNFA()
{
    static const char rname[] = "~KissThinNFA";
    // the code here was once in kiss_thin_nfa_destroy
    u_int bnfa_size = max_bnfa_offset - min_bnfa_offset;

    thinnfa_debug_major(("%s: Destroying Thin NFA %p, bnfa size=%d\n", rname,
        this, bnfa_size));

    if(bnfa_start != NULL) {
        kiss_pmglob_memory_kfree(bnfa_start, bnfa_size, rname);
        bnfa_start = NULL;
        bnfa = NULL;
    }

    kiss_thin_nfa_stats_free(&stats);

    if (pattern_arrays != NULL) {
        kiss_pmglob_memory_kfree(pattern_arrays, pattern_arrays_size, rname);
        pattern_arrays = NULL;
    }

    kiss_thin_nfa_destroy_depth_map(this);
}


// Allocate a Thin NFA. The match info array and BNFA are left empty.
std::unique_ptr<KissThinNFA>
kiss_thin_nfa_create(u_int match_state_num, kiss_bnfa_offset_t min_offset, kiss_bnfa_offset_t max_offset)
{
    static const char rname[] = "kiss_thin_nfa_create";

    // Allocate the structure
    auto nfa = std::make_unique<KissThinNFA>();
    void *nfa_ptr = nfa.get();
    bzero(nfa_ptr, sizeof(*nfa));
    nfa->min_bnfa_offset = min_offset;
    nfa->max_bnfa_offset = max_offset;
    nfa->match_state_num = match_state_num;

    // Allocate the bnfa array. Not initialized.
    u_int bnfa_size = max_offset - min_offset;
    nfa->bnfa_start = (kiss_bnfa_state_t *)kiss_pmglob_memory_kmalloc_ex(bnfa_size, rname, FW_KMEM_SLEEP);
    if (!nfa->bnfa_start) {
        thinnfa_debug_err((
            "%s: Error allocating the bnfa - size %d (offset %d:%d)\n",
            rname,
            bnfa_size,
            min_offset,
            max_offset
        ));
        return nullptr;
    }

    // Calculate bnfa so bnfa_start would be at offset min_offset (min_offset<0, so bnfa>bnfa_start)
    nfa->bnfa = (kiss_bnfa_state_t *)((char *)nfa->bnfa_start - min_offset);

    // Init the statistics
    if (kiss_thin_nfa_stats_init(&(nfa->stats)) != KISS_OK) {
        thinnfa_debug_err(("%s: Error initializing statistics structure\n", rname));
        return nullptr;
    }

    // Allocate the state depth map
    if (kiss_thin_nfa_alloc_depth_map(nfa.get()) != KISS_OK) {
        return nullptr;
    }

    thinnfa_debug_major((
        "%s: Allocated Thin NFA %p, bnfa size=%d (offsets %d:%d)\n",
        rname,
        nfa.get(),
        bnfa_size,
        min_offset,
        max_offset
    ));

    return nfa;
}
