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

#ifndef __kiss_pm_stats_h__
#define __kiss_pm_stats_h__

#include "pm_adaptor.h"

// Common statistics

// Common run time statistics
struct kiss_pm_stats_dynamic_s {
    u_int num_of_buffs;        // Number of buffers we ran this dfa on
    u_int num_of_matches;      // how many matches there were in this dfa
    u_int max_matches_on_buf;  // Maximal number of matches per one buf

    struct {               // Buffer length statistics
        u_int max;         // Maximum buffer length
        u_int total;       // Total length (for average calculation)
        u_int sample_num;  // Number of buffers, whose lengths make up total.
    } buflen;

    struct {                         // Execution time statistics - not collected by default
        u_int total_exec_time;       // PM Execution time (not including user callbacks)
        u_int max_exec_time;         // Maximal PM execution time
        u_int user_cb_exec_time;     // User callback execution time
        u_int user_cb_max_time;      // Maximal user callback execution time
        u_int sample_num;            // Number of execution time samples
    } runtime;

    u_int num_of_stage1_matches;  // Tier1 LSS matches, before filtering by mask
    u_int num_of_stage22_matches; // Tier1 matches after ^
    u_int num_of_stage23_matches; // Tier1 matches after $
};

// Common build time statistics
struct kiss_pm_stats_static_s {
    u_int memory_bytes;            // How many bytes does this tier consume
    u_int compilation_time;        // Compilation time of this tier in micro-seconds
};

struct CP_CACHELINE_ALIGNED kiss_pm_stats_dynamic_aligned_s {
    struct kiss_pm_stats_dynamic_s stats;
};

struct kiss_pm_stats_common_s {
    // Run time statistics, per-CPU, dynamically allocated
    struct kiss_pm_stats_dynamic_aligned_s* exec;
    // Size of the exec array
    u_int exec_num_cpus;
    // Build time statistics
    struct kiss_pm_stats_static_s compile;
};

typedef struct kiss_pm_stats_common_s *kiss_pm_stats_common;

enum kiss_pm_stats_update_compile_type {
    UPDATE_COMPILE_STATS_MEM,
    UPDATE_COMPILE_STATS_TIME,
    UPDATE_COMPILE_STATS_BOTH
};

// In which format the statistics should be printed
enum kiss_pm_stats_format {
    KISS_PM_TEXT_FORMAT_STATS = 0, // Textual, for viewing with text editor
    KISS_PM_CSV_FORMAT_STATS       // CSV, for opening with Excel
};

KISS_APPS_CPAPI
kiss_ret_val kiss_pm_stats_common_init(kiss_pm_stats_common new_stats);

KISS_APPS_CPAPI
void kiss_pm_stats_common_free(kiss_pm_stats_common stats);

KISS_APPS_CPAPI
void kiss_pm_stats_common_update_compile(
    kiss_pm_stats_common stats,
    u_int bytes,
    u_int compilation_time,
    enum kiss_pm_stats_update_compile_type type);

KISS_APPS_CPAPI
void kiss_pm_stats_common_update_exec(kiss_pm_stats_common stats, u_int buf_size, u_int num_of_matches);


// @brief
//    Updating the execution time of an execution of a buffer in tier2.
//
// @param stats - [in] The tier2 common stats.
// @param exec_time - [in] The execution time.
// @param buf_len - [in] the length of the last buffer that was executed
//
// @return Void
//
// @note
//    in case one of the stats vars will warp-around, the aggregated vars will hold only the last exec stats.
KISS_APPS_CPAPI
void kiss_pm_stats_common_update_exec_time(kiss_pm_stats_common stats, u_int exec_time, u_int user_cb_time);

KISS_APPS_CPAPI
void kiss_pm_stats_common_reset_exec(kiss_pm_stats_common stats);

KISS_APPS_CPAPI
void kiss_pm_stats_common_print(
    kiss_pm_stats_common stats,
    enum kiss_pm_stats_type type,
    enum kiss_pm_stats_format format,
    BOOL print_headline
);

KISS_APPS_CPAPI
kiss_ret_val kiss_pm_stats_common_get(
    struct kiss_pm_stats_static_s *dst_compile,
    struct kiss_pm_stats_dynamic_s *dst_exec,
    const struct kiss_pm_stats_common_s *src
);

KISS_APPS_CPAPI
kiss_ret_val kiss_pm_stats_common_copy(kiss_pm_stats_common dst, const struct kiss_pm_stats_common_s *src);

KISS_APPS_CPAPI
u_int kiss_pm_stats_common_get_serialize_size(void);

KISS_APPS_CPAPI
kiss_ret_val kiss_pm_stats_common_serialize(const struct kiss_pm_stats_common_s *stats, u_char **buf, u_int *size);

KISS_APPS_CPAPI
kiss_ret_val kiss_pm_stats_common_deserialize(
    kiss_pm_stats_common stats,
    u_char **buf,
    u_int *size,
    kiss_vbuf vbuf,
    kiss_vbuf_iter *vbuf_iter
);

#endif // __kiss_pm_stats_h__
