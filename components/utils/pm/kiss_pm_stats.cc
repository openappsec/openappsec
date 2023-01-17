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

#include "general_adaptor.h"
// ********************* INCLUDES **************************
#include "kiss_pm_stats.h"
// ********************* INCLUDES **************************

// ********************* FUNCTIONS **************************


// Initialize the common statistics
kiss_ret_val
kiss_pm_stats_common_init(kiss_pm_stats_common new_stats)
{
    static const char rname[] = "kiss_pm_stats_common_init";

    if (new_stats == NULL) {
        kiss_debug_err(K_PM, ("%s: stats is zero\n", rname));
        return KISS_ERROR;
    }

    bzero(new_stats, sizeof(struct kiss_pm_stats_common_s));

#if 0
    if (kiss_pm_stats_take_exec_time) {
        new_stats->exec_num_cpus = kiss_multik_instance_num;
        new_stats->exec = kiss_pmglob_memory_kmalloc_ex(
            new_stats->exec_num_cpus * sizeof(struct kiss_pm_stats_dynamic_aligned_s),
            rname,
            (FW_KMEM_NOSLEEP| FW_KMEM_RETURN_ALIGN_PTR)
        );

        if (!new_stats->exec) {
            kiss_debug_err(K_PM, ("%s: Error in allocating the execution stats\n", rname));
            return KISS_ERROR;
        }

        bzero(new_stats->exec, new_stats->exec_num_cpus*sizeof(struct kiss_pm_stats_dynamic_aligned_s));
    }
#endif

    return KISS_OK;

}

#define KISS_MULTIK_MAX_INSTANCE_NUM 40

// Free the common statistics
void
kiss_pm_stats_common_free(kiss_pm_stats_common stats)
{
    static const char rname[] = "kiss_pm_stats_common_free";
    BOOL should_free_stats_exec =
        stats &&
        stats->exec &&
        stats->exec_num_cpus > 0 &&
        stats->exec_num_cpus < KISS_MULTIK_MAX_INSTANCE_NUM;
    if (should_free_stats_exec) {
        kiss_pmglob_memory_kfree(
            stats->exec,
            stats->exec_num_cpus * sizeof(struct kiss_pm_stats_dynamic_aligned_s),
            rname
        );
        stats->exec = NULL;
    }
    return;
}

// Update build-time statistics
void
kiss_pm_stats_common_update_compile(kiss_pm_stats_common stats, u_int bytes, u_int compilation_time,
                                                enum kiss_pm_stats_update_compile_type type)
{
    KISS_ASSERT_PERF(stats, ("Illegal arguments"));

    switch (type) {
        case UPDATE_COMPILE_STATS_MEM:
            stats->compile.memory_bytes = bytes;
            return;
        case UPDATE_COMPILE_STATS_TIME:
            stats->compile.compilation_time = compilation_time;
            return;
        case UPDATE_COMPILE_STATS_BOTH:
            stats->compile.memory_bytes = bytes;
            stats->compile.compilation_time = compilation_time;
            return;
    }
}


// Will adding to an unsigned variable cause it to wrap around?
#define ADDITION_WOULD_WRAP_AROUND(old_val, delta)        \
    ((old_val) + (delta) < (old_val))

// Reset buffer length statistics, so we can add a buffer without wraparound
static void
handle_buflen_stats_wraparound(struct kiss_pm_stats_dynamic_s *cur_kern_inst_stats)
{
    cur_kern_inst_stats->buflen.total = 0;
    cur_kern_inst_stats->buflen.sample_num = 0;
}

// Reset execution time statistics, so we can add a sample without wraparound
static void
handle_runtime_stats_wraparound(struct kiss_pm_stats_dynamic_s *cur_kern_inst_stats)
{
    cur_kern_inst_stats->runtime.total_exec_time = 0;
    cur_kern_inst_stats->runtime.user_cb_exec_time = 0;
    cur_kern_inst_stats->runtime.sample_num = 0;
}


// Update run-time statistics
void
kiss_pm_stats_common_update_exec(kiss_pm_stats_common stats, u_int buf_size, u_int num_of_matches)
{
    struct kiss_pm_stats_dynamic_s *cur_kern_inst_stats;
    KISS_ASSERT_PERF(stats, ("Illegal arguments"));
    if(stats->exec) {
        ASSERT_LOCKED;
        cur_kern_inst_stats = &(stats->exec[kiss_multik_this_instance_num].stats);

        // Buffer length statistics
        if (ADDITION_WOULD_WRAP_AROUND(cur_kern_inst_stats->buflen.total, buf_size)) {
            handle_buflen_stats_wraparound(cur_kern_inst_stats);
        }
        cur_kern_inst_stats->buflen.total += buf_size;
        cur_kern_inst_stats->buflen.sample_num++;
        if (buf_size > cur_kern_inst_stats->buflen.max) {
            cur_kern_inst_stats->buflen.max = buf_size;
        }

        // General statistics
        cur_kern_inst_stats->num_of_buffs++;
        cur_kern_inst_stats->num_of_matches += num_of_matches;
        if (num_of_matches > cur_kern_inst_stats->max_matches_on_buf) {
            cur_kern_inst_stats->max_matches_on_buf = num_of_matches;
        }
    }

    return;
}

// Update run-time (execution) statistics
void
kiss_pm_stats_common_update_exec_time(kiss_pm_stats_common stats, u_int exec_time, u_int user_cb_time)
{
    struct kiss_pm_stats_dynamic_s *cur_kern_inst_stats;
    if(stats && stats->exec) {
        ASSERT_LOCKED;
        cur_kern_inst_stats = &(stats->exec[kiss_multik_this_instance_num].stats);

        // The execution time includes the callback, but we want the net time.
        exec_time -= user_cb_time;

        // take care of wrap around
        if (ADDITION_WOULD_WRAP_AROUND(cur_kern_inst_stats->runtime.total_exec_time, exec_time) ||
                ADDITION_WOULD_WRAP_AROUND(cur_kern_inst_stats->runtime.user_cb_exec_time, user_cb_time)) {
            handle_runtime_stats_wraparound(cur_kern_inst_stats);
        }
        cur_kern_inst_stats->runtime.total_exec_time += exec_time;
        cur_kern_inst_stats->runtime.user_cb_exec_time += user_cb_time;
        cur_kern_inst_stats->runtime.sample_num++;

        // Updating the max values
        if (exec_time > cur_kern_inst_stats->runtime.max_exec_time){
            cur_kern_inst_stats->runtime.max_exec_time = exec_time;
        }
        if (user_cb_time > cur_kern_inst_stats->runtime.user_cb_max_time){
            cur_kern_inst_stats->runtime.user_cb_max_time = user_cb_time;
        }
    }
    return;
}


// Clear all runtime statistics
void
kiss_pm_stats_common_reset_exec(kiss_pm_stats_common stats)
{
    u_int i;
    if(stats && stats->exec) {
        for (i = 0; i < stats->exec_num_cpus; i++) {
            struct kiss_pm_stats_dynamic_s *cur_cpu_stats;
            cur_cpu_stats = &(stats->exec[i].stats);
            bzero(cur_cpu_stats, sizeof(*cur_cpu_stats));
        }
    }
}


// Aggregate the run-time statistics from all cpus in src to dst
static void
kiss_pm_stats_common_aggregate_cpus(struct kiss_pm_stats_dynamic_s *dst, const struct kiss_pm_stats_common_s *src)
{
    u_int i;
    KISS_ASSERT_PERF(src, ("Illegal arguments"));
    if(src && src->exec)
    {
        for (i = 0; i < src->exec_num_cpus; i++) {
            struct kiss_pm_stats_dynamic_s *cur_cpu_src = &(src->exec[i].stats);

            // Buffer length statistics - add and avoid wrap-around
            if (ADDITION_WOULD_WRAP_AROUND(dst->buflen.total, cur_cpu_src->buflen.total)) {
                handle_buflen_stats_wraparound(dst);
            }
            dst->buflen.total += cur_cpu_src->buflen.total;
            dst->buflen.sample_num += cur_cpu_src->buflen.sample_num;
            dst->buflen.max = MAX(dst->buflen.max, cur_cpu_src->buflen.max);

            // General statistics
            dst->num_of_matches += cur_cpu_src->num_of_matches;
            dst->num_of_stage1_matches += cur_cpu_src->num_of_stage1_matches;
            dst->num_of_stage22_matches += cur_cpu_src->num_of_stage22_matches;
            dst->num_of_stage23_matches += cur_cpu_src->num_of_stage23_matches;

            dst->num_of_buffs += cur_cpu_src->num_of_buffs;
            if (dst->max_matches_on_buf < cur_cpu_src->max_matches_on_buf) {
                dst->max_matches_on_buf = cur_cpu_src->max_matches_on_buf;
            }

            // Execution time statistics - add and avoid wrap-around
            if (ADDITION_WOULD_WRAP_AROUND(dst->runtime.total_exec_time, cur_cpu_src->runtime.total_exec_time) ||
                ADDITION_WOULD_WRAP_AROUND(dst->runtime.user_cb_exec_time, cur_cpu_src->runtime.user_cb_exec_time)) {
                handle_runtime_stats_wraparound(dst);
            }
            dst->runtime.total_exec_time += cur_cpu_src->runtime.total_exec_time;
            dst->runtime.user_cb_exec_time += cur_cpu_src->runtime.user_cb_exec_time;
            dst->runtime.sample_num += cur_cpu_src->runtime.sample_num;
            dst->runtime.max_exec_time = MAX(dst->runtime.max_exec_time, cur_cpu_src->runtime.max_exec_time);
            dst->runtime.user_cb_max_time = MAX(dst->runtime.user_cb_max_time, cur_cpu_src->runtime.user_cb_max_time);
        }
    }
    return;
}

#define TOTAL_MICORSEC_TO_AVG_NSEC(total, samples)    \
    ((samples)==0 ? 0 : (u_int)((u_int64)(total) * 1000 / (u_int64)(samples)))

// Print the common statistics
void
kiss_pm_stats_common_print(
    kiss_pm_stats_common stats,
    enum kiss_pm_stats_type type,
    enum kiss_pm_stats_format format,
    BOOL print_headline
)
{
    struct kiss_pm_stats_dynamic_s dynamic_stats;
    KISS_ASSERT_PERF((stats && !print_headline) || print_headline, ("Illegal arguments"));

    if (type != KISS_PM_DYNAMIC_STATS) {
        if (format == KISS_PM_TEXT_FORMAT_STATS) {
            kdprintf("Memory comsumption for this handle is %u bytes\n", stats->compile.memory_bytes);
            kdprintf("Compilation time for this handle is %u microseconds\n", stats->compile.compilation_time);
        } else if (format == KISS_PM_CSV_FORMAT_STATS) {
            if (print_headline) {
                kdprintf("Memory consumption;Compilation time (microsec);");
            } else {
                kdprintf("%u;%u;", stats->compile.memory_bytes, stats->compile.compilation_time);
            }
        }
    }

    if (!print_headline) {
        bzero(&dynamic_stats, sizeof(struct kiss_pm_stats_dynamic_s ));
        kiss_pm_stats_common_aggregate_cpus(&dynamic_stats, stats);
    }

    if (type != KISS_PM_STATIC_STATS) {
        if (format == KISS_PM_TEXT_FORMAT_STATS) {
            kdprintf("Number of executed buffers is %u\n", dynamic_stats.num_of_buffs);
            kdprintf("Max buffer length is %u\n", dynamic_stats.buflen.max);
            kdprintf("Avg buffer length is %u\n",
                dynamic_stats.buflen.sample_num ? (dynamic_stats.buflen.total/dynamic_stats.buflen.sample_num) : 0);
            kdprintf("Number of matches is %u\n", dynamic_stats.num_of_matches);
            kdprintf("Number of matches after stage1 is %u\n", dynamic_stats.num_of_stage1_matches);
            kdprintf("Number of matches after start-anchor is %u\n", dynamic_stats.num_of_stage22_matches);
            kdprintf("Number of matches after end-anchor is %u\n", dynamic_stats.num_of_stage23_matches);
            kdprintf("Max number of matches on buffer is %u\n", dynamic_stats.max_matches_on_buf);
            // Average execution time - display in nanosecond so rounding down won't lose too much
            kdprintf("Avg execution time is %u ns for PM, %u ns for callbacks\n",
                TOTAL_MICORSEC_TO_AVG_NSEC(dynamic_stats.runtime.total_exec_time, dynamic_stats.runtime.sample_num),
                TOTAL_MICORSEC_TO_AVG_NSEC(dynamic_stats.runtime.user_cb_exec_time, dynamic_stats.runtime.sample_num));
            // Maximum execution time - display in nanosecond for consistency with average.
            // concatenate 000 instead of multiplying,
            // to avoid overflow (in very extreme, yet very interesting, cases).
            kdprintf("Max execution time is %u000 ns for PM, %u000 ns for callbacks\n",
                dynamic_stats.runtime.max_exec_time, dynamic_stats.runtime.user_cb_max_time);
        } else if (format == KISS_PM_CSV_FORMAT_STATS) {
            if (print_headline) {
                kdprintf(
                    "Executed buffers #;"
                    "Max buffer length;"
                    "Avg buffer length;"
                    "Matches #;"
                    "Max matches on buffer;"
                    "stage1 matches #;"
                    "2nd filter matches #;"
                    "3rd filter matches #;"
                    "Avg PM exec time (ns);"
                    "Max PM exec time (ns);"
                    "Avg callback exec time (ns);"
                    "Max callback exec time (ns)"
                );
            } else {
                kdprintf("%u;%u;%u;%u;%u;%u;%u;%u;%u;%u000;%u;%u000",
                    dynamic_stats.num_of_buffs,
                    dynamic_stats.buflen.max,
                    dynamic_stats.buflen.sample_num ? (dynamic_stats.buflen.total/dynamic_stats.buflen.sample_num) : 0,
                    dynamic_stats.num_of_matches,
                    dynamic_stats.max_matches_on_buf,
                    dynamic_stats.num_of_stage1_matches,
                    dynamic_stats.num_of_stage22_matches,
                    dynamic_stats.num_of_stage23_matches,
                    TOTAL_MICORSEC_TO_AVG_NSEC(
                        dynamic_stats.runtime.total_exec_time,
                        dynamic_stats.runtime.sample_num
                    ),
                    dynamic_stats.runtime.max_exec_time,
                    TOTAL_MICORSEC_TO_AVG_NSEC(
                        dynamic_stats.runtime.user_cb_exec_time,
                        dynamic_stats.runtime.sample_num
                    ),
                    dynamic_stats.runtime.user_cb_max_time
                );
            }
        }
    }

    return;
}

#define kiss_pm_serialize_during_sanity_check 0


// Return the statistics from src in dst (aggregate statistics from all cpus)
kiss_ret_val
kiss_pm_stats_common_get(struct kiss_pm_stats_static_s *dst_compile,
                                struct kiss_pm_stats_dynamic_s *dst_exec,
                                const struct kiss_pm_stats_common_s *src)
{
    KISS_ASSERT_PERF((dst_compile && dst_exec && src), ("Illegal arguments"));

    if (!(dst_compile && dst_exec && src)) {
        return KISS_ERROR;
    }
    bzero(dst_compile, sizeof(struct kiss_pm_stats_static_s));
    bzero(dst_exec, sizeof(struct kiss_pm_stats_dynamic_s));
    bcopy(&(src->compile), dst_compile, sizeof(struct kiss_pm_stats_static_s));

    kiss_pm_stats_common_aggregate_cpus(dst_exec, src);

    // for debug purposes only!
    // ignore specific statistics fields when performing a sanity check on serialization
    if (kiss_pm_serialize_during_sanity_check) {
        dst_compile->memory_bytes = KISS_PM_SERIALIZE_IGNORE_INT;
        dst_compile->compilation_time = KISS_PM_SERIALIZE_IGNORE_INT;
    }

    return KISS_OK;
}

// Copy the statistics from src to dst
kiss_ret_val
kiss_pm_stats_common_copy(kiss_pm_stats_common dst, const struct kiss_pm_stats_common_s *src)
{
    if(src && src->exec) {
        u_int num_cpus = MIN(src->exec_num_cpus, dst->exec_num_cpus);
        KISS_ASSERT_PERF((dst && src), ("Illegal arguments"));

        if (!(dst && src)) {
            return KISS_ERROR;
        }
        bcopy(&(src->compile), &(dst->compile), sizeof(struct kiss_pm_stats_static_s));
        bcopy(src->exec, dst->exec, num_cpus*sizeof(struct kiss_pm_stats_dynamic_aligned_s));
    }
    return KISS_OK;
}

// Get size of serialized common statistics. Only build-time statistics are counted
u_int
kiss_pm_stats_common_get_serialize_size()
{
    return sizeof(struct kiss_pm_stats_static_s);
}

// Serialize common statistics. Only build-time statistics are serialized
kiss_ret_val
kiss_pm_stats_common_serialize(const struct kiss_pm_stats_common_s *stats, u_char **buf, u_int *size)
{
    KISS_ASSERT_PERF((stats), ("Illegal arguments"));

    DATA_BUFF_COPY(*buf, size, &(stats->compile), sizeof(struct kiss_pm_stats_static_s));

    return KISS_OK;
}

// Deserialize common statistics. Only build-time statistics are deserialized
kiss_ret_val
kiss_pm_stats_common_deserialize(
    kiss_pm_stats_common stats,
    u_char **buf, u_int *size,
    CP_MAYBE_UNUSED kiss_vbuf vbuf,
    CP_MAYBE_UNUSED kiss_vbuf_iter *vbuf_iter
)
{
    KISS_ASSERT_PERF((stats), ("Illegal arguments"));

    DATA_BUFF_READ(*buf, size, vbuf, *vbuf_iter, &(stats->compile), sizeof(struct kiss_pm_stats_static_s));

    return KISS_OK;
}

// ******************** FUNCTIONS *************************
