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

#ifndef KERNEL

#if defined(VXWORKS) || defined(freebsd) || defined (solaris2)
#include <stdlib.h>
#elif defined (ARMON)
#include <memLib.h>
// #include <stdioLib.h>
#elif defined(SYS_PSOS)
#include <prepc.h>
#else
#include <stdio.h>
#endif

#endif // KERNEL

#include "kiss_hash.h"

// we provide  hash_craete, hash_create_with_destr function implementations
#undef kiss_hash_create
#undef kiss_hash_create_with_destr

#ifndef NULL
#define NULL 0
#endif
#ifndef HASH_DEFAULT_SIZE
#define HASH_DEFAULT_SIZE 1024
#endif

static void KissHashResizeMode_reset_parameters(KissHashResizeMode *resize_mode);
static void KissHashResizeMode_set_default_parameters(KissHashResizeMode *resize_mode);
static int  KissHashResizeMode_verify_method(const KissHashResizeMode *resize_mode);
static int  KissHashResizeMode_verify_value(const KissHashResizeMode *resize_mode);
static int  KissHashResizeMode_verify_trigger_ratio(const KissHashResizeMode *resize_mode);
static int  KissHashResizeMode_verify_direction(const KissHashResizeMode *resize_mode);
static int  kiss_hash_do_resize(kiss_hash_t hp, const KissHashResizeMode *resize_mode);
static boolean_cpt kiss_hash_resize_check_for_resize(kiss_hash_t hp, KissHashResizeDirection direction);

struct _KissHashResizeMode {
    u_int max_size;
    KissHashResizeMethod method;
    KissHashResizeDirection direction;
    u_int value;
    u_int trigger_ratio;
    HashResizeCb_t cb;
};

struct kiss_hash {
    char *file;          // source file name where hash was created
    int line;            // line number where hash was created
    int hash_index;
    struct kiss_hashent **h_tab;
    int h_nelements;
    int h_sz;
    int h_orig_size;
    KissHashResizeMode h_resize_mode;
    int h_dodestr;
    uintptr_t (*h_keyfunc)(const void *key, void *info);
    int (*h_keycmp)(const void *key1, const void *key2, void *info);
    void (*h_val_destr)(void *val);
    void (*h_key_destr)(void *key);
    void *h_info;
};

struct kiss_hash_iter {
    kiss_hash_t hash;
    int slot;
    struct kiss_hashent *pntr;
};

// pointers to created hash tables
#ifdef HASH_DEBUG
#define MAX_HASHES 1024
static kiss_hash_t kiss_hashes[MAX_HASHES];
static int kiss_curr_hash = 0;
static int do_kiss_hash_debug = 0;
static int kiss_checked_env = 0;

static void dbg_register_hash(kiss_hash_t hash, int line, const char *file) {

    hash->line = line;
        hash->file = (char *) file;

    if (kiss_checked_env && !do_kiss_hash_debug)
        return;

    if (!kiss_checked_env) {
        if (getenv("CP_HASH_DEBUG"))
            do_kiss_hash_debug = 1;
        kiss_checked_env = 1;
    }

    MtBeginCS();
        if (kiss_curr_hash != MAX_HASHES) {
            kiss_hashes[kiss_curr_hash] = hash;
            hash->hash_index = kiss_curr_hash++;
        }
        else
            hash->hash_index = -1;
        MtEndCS();

}

static void dbg_deregister_hash(kiss_hash_t hash) {

    if ((kiss_checked_env && !do_kiss_hash_debug) || !kiss_checked_env)
        return;

    if (hash->hash_index == -1)
        return;

    MtBeginCS();
    if (kiss_curr_hash > 0) {
        kiss_curr_hash--;
        kiss_hashes[hash->hash_index] = kiss_hashes[kiss_curr_hash];
    }
    MtEndCS();

}


//    @name Hash functions
//
//
//
//  Debug single hash.

//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  This function calculates and prints the following statistics:
//  \begin{itemize}
//  \item hash pointer
//  \item file name and line number where \Ref{hash_create} or \Ref{hash_create_with_destr} was called
//  \item number of elements in hash
//  \item number of slots in hash - hash size
//  \item size in bytes of memory occupied by hash maintenance structures
//  \item slot utilzation - percentage of hash slots used to store elements
//  \item average number of lookups - average length of lists of elements
//  \end{itemize}
//
//  @param hash  pointer to hash
//  @return size in bytes of memory occupied by hash maintenance structures.
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp,
//  kiss_hash_debug_all
int kiss_hash_debug(kiss_hash_t hash) {

    int slot, used_slots=0;
    double slot_utilization, avg_lookup;
    int kiss_hash_size = hash->h_sz;
    int mem_size =
        sizeof(struct kiss_hash) +
        kiss_hash_size * sizeof(struct kiss_hashent*) +
        hash->h_nelements*sizeof(struct kiss_hashent);

        // check slot utilization
        for (slot=0; slot<kiss_hash_size; slot++) {
            if (hash->h_tab[slot]) used_slots++;
        }

    slot_utilization = (double) used_slots/kiss_hash_size;
    avg_lookup = (used_slots) ? (double) hash->h_nelements/used_slots : 0;

    error(
        0,
        0,
        "hash 0x%x created in %s:%d : nelements=%d kiss_hash_size=%d "
        "mem_size=%d slot_utilzation %f (%d of %d) avg lookup %f",
        hash,
        hash->file,
        hash->line,
        hash->h_nelements,
        kiss_hash_size,
        mem_size,
        slot_utilization,
        used_slots,
        kiss_hash_size,
        avg_lookup
    );

    return mem_size;
}


//    Debug single hash.
//
//    \begin{description}
//    \item[ MT-Level: ] Safe
//    \end{description}
//
//    Iterates a list of all hash tables craeted in the current process and
//    for each hash calls function \Ref{kiss_hash_debug}. In addition the total
//    memory usage of hash maintenance structures is printed.
//
//    @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//    kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//    kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//    kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug
void kiss_hash_debug_all() {
    int i, total_mem_size=0;

    if ((kiss_checked_env && !do_kiss_hash_debug) || !kiss_checked_env) return;

    MtBeginCS();
    error(0, 0, "[%s] Hash Debug", ltime(0));
    for (i=0; i<kiss_curr_hash; i++) {
        total_mem_size += kiss_hash_debug(kiss_hashes[i]);
    }

    error(0, 0, "Total memory size used by hash: %d", total_mem_size);
    MtEndCS();
}
#endif // HASH_DEBUG

static int
roundtwo(int n)
{
    int i=2;
    for (i = 1 ; i < n; i <<= 1);
    return i;
}

static void hent_destroy(kiss_hash_t hp, struct kiss_hashent *he, int dod)
{
    if( dod || hp->h_dodestr) {
        H_DESTR(hp->h_val_destr, he->val);
        H_DESTR(hp->h_key_destr, he->key);
    }
}


//    Number of hash elements.
//
//    \begin{description}
//    \item[ MT-Level: ] Reentrant
//    \end{description}
//
//    @param hash hash table
//    @return number of elements
//    @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//    kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//    kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//    kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
int
kiss_hash_nelements(kiss_hash_t hash)
{
    return hash->h_nelements;
}


//  Hash size.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hash hash table
//  @return Size of hash
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
int
kiss_hash_get_size(kiss_hash_t hash)
{
    return hash->h_sz + 1;    // In hash create we decrease by 1 the application size
}


//  Hash orignal size.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hash hash table
//  @return Original size of hash (for hash tables with dynamic size).
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
int kiss_hash_orig_size(kiss_hash_t hash)
{
    return hash->h_orig_size + 1;    // In hash create we decrease by 1 the application size
}

static kiss_hash_t
kiss_hash_create_do(size_t hsize,
            hkeyfunc_t keyfunc,
            hcmpfunc_t keycmp,
            void *info,
            boolean_cpt  do_kernel_sleep)
{
    extern int roundtwo(int n);

    kiss_hash_t hp;

    if (hsize == 0) hsize = HASH_DEFAULT_SIZE;

    hsize = roundtwo(hsize);

    if(do_kernel_sleep) {
        hp = (kiss_hash_t)kiss_pmglob_memory_kmalloc_ex_(
            sizeof(struct kiss_hash),
            "kiss_hash_create",
            FW_KMEM_SLEEP,
            __FILE__,
            __LINE__
        );
    } else {
        hp = (kiss_hash_t)kiss_pmglob_memory_kmalloc((sizeof(struct kiss_hash)), "kiss_hash_create");
    }

    if (hp == NULL) return NULL;
    memset(hp, 0, sizeof(struct kiss_hash));

    if(do_kernel_sleep) {
        hp->h_tab = (struct kiss_hashent **)kiss_pmglob_memory_kmalloc_ex_(
            (sizeof(struct kiss_hashent *)) * hsize,
            "kiss_hash_create",
            FW_KMEM_SLEEP,
            __FILE__,
            __LINE__
        );
    } else {
        hp->h_tab = (struct kiss_hashent **)kiss_pmglob_memory_kmalloc(
            (sizeof(struct kiss_hashent *)) * hsize,
            "kiss_hash_create"
        );
    }

    if (!hp->h_tab) {
        kiss_pmglob_memory_kfree(hp, sizeof(struct kiss_hash), "kiss_hash_create");
        return NULL;
    }

    memset(hp->h_tab, 0, (sizeof(struct kiss_hashent *) * hsize));

    hp->h_sz = hsize - 1;
    hp->h_orig_size = hp->h_sz;
    hp->hash_index = -1;
    hp->h_keyfunc = keyfunc == (hkeyfunc_t)kiss_hash_intvalue ? 0 : keyfunc;
    hp->h_keycmp = keycmp == (hcmpfunc_t)kiss_hash_intcmp ? 0 : keycmp;
    hp->h_val_destr = hp->h_key_destr = NULL;
    hp->h_info = info;
    hp->h_nelements = 0;
    hp->h_dodestr = 0;
    KissHashResizeMode_reset_parameters(&(hp->h_resize_mode));

    return hp;
}


//  Create Hash Table.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hsize  hash size
//  @param keyfunc key hashing function
//  @param keycmp  key comparison function
//  @param info//  opaque for use of {\tt keyfunc} and {\tt keycmp} functions.
//  @return hash pointer or NULL upon failure.
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
//  note: to create a large hash in kernel mode using kmalloc_sleep call function _kiss_hash_create_with_ksleep or
//  Macro _kiss_hash_create_with_ksleep.
kiss_hash_t
kiss_hash_create(size_t hsize,
            hkeyfunc_t keyfunc,
            hcmpfunc_t keycmp,
            void *info)
{
    return kiss_hash_create_do(hsize, keyfunc, keycmp, info, FALSE);
}

kiss_hash_t
_kiss_hash_create(size_t hsize,
            hkeyfunc_t keyfunc,
            hcmpfunc_t keycmp,
            void *info, CP_MAYBE_UNUSED const char *file, CP_MAYBE_UNUSED int line)
{
    kiss_hash_t hash;
    hash = kiss_hash_create_do(hsize, keyfunc, keycmp, info, FALSE);

#ifdef HASH_DEBUG
    if (hash) dbg_register_hash(hash, line, file);
#endif

    return hash;
}

kiss_hash_t
_kiss_hash_create_with_ksleep(size_t hsize,
            hkeyfunc_t keyfunc,
            hcmpfunc_t keycmp,
            void *info, CP_MAYBE_UNUSED const char *file, CP_MAYBE_UNUSED int line)
{
    kiss_hash_t hash;
    hash = kiss_hash_create_do(hsize, keyfunc, keycmp, info, TRUE);

#ifdef HASH_DEBUG
    if (hash) dbg_register_hash(hash, line, file);
#endif

    return hash;
}


//  Set destructor for hash elements.
//
//  Keys and values detsructors are called for every hash key-value pair
//  when the hash is destroyed.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash
//  @param val_destr destructor for the values of the hash
//  @param key_destr destructor for the keys of the hash
//  @return hash pointer
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
kiss_hash_t
kiss_hash_set_destr(kiss_hash_t hp, freefunc_t val_destr, freefunc_t key_destr)
{
    if (!hp) return NULL;

    hp->h_val_destr = val_destr;
    hp->h_key_destr = key_destr;

    return hp;
}


//  This tells the hash to automaticly call destructors when an entry gets
//  deleted from the hash. Usualy this is not the case !
//
//  Enable hash element detsruction.
//
//  Hash is created with destruction of elements disabled by default.
//  This functions enables destruction upon a call to \ref{kiss_hash_destroy}.

//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
void
kiss_hash_dodestr(kiss_hash_t hp)
{
    hp->h_dodestr=1;
}


// What's done must (have a way to) be undone.
//
//
//    Disable hash element detsruction.
//    \begin{description}
//    \item[ MT-Level: ] Reentrant
//    \end{description}
//
//    @param hp hash
//    @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//    kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//    kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//    kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
void
kiss_hash_undo_destr(kiss_hash_t hp)
{
    hp->h_dodestr = 0;
}


//    Create Hash Table with Destructor.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hsize  hash size
//  @param keyfunc key hashing function
//  @param keycmp  key comparison function
//  @param val_destr destructor for the values of the hash
//  @param key_destr destructor for the keys of the hash
//  @param info//  opaque for use of {\tt keyfunc} and {\tt keycmp} functions.
//  @return hash pointer or NULL upon failure.
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
kiss_hash_t
kiss_hash_create_with_destr(
    size_t hsize,
    hkeyfunc_t keyfunc,
    hcmpfunc_t keycmp,
    freefunc_t val_destr,
    freefunc_t key_destr,
    void *info
)
{
    kiss_hash_t hp;

    if ((hp = kiss_hash_create(hsize, keyfunc, keycmp, info)) == NULL) return NULL;

    return kiss_hash_set_destr(hp, val_destr, key_destr);
}

kiss_hash_t
_kiss_hash_create_with_destr(
    size_t hsize,
    hkeyfunc_t keyfunc,
    hcmpfunc_t keycmp,
    freefunc_t val_destr,
    freefunc_t key_destr,
    void *info, CP_MAYBE_UNUSED const char *file,
    CP_MAYBE_UNUSED int line)
{
    kiss_hash_t hash;
    hash = kiss_hash_create_with_destr(hsize, keyfunc, keycmp, val_destr, key_destr, info);

#ifdef HASH_DEBUG
    if (hash) dbg_register_hash(hash, line, file);
#endif

    return hash;
}


//  Find hash entry.
//
//  The next routine is used as an efficient but somewhat ugly interface for
//  find/insert operation. What it does is to return an adrress of a pointer
//  to a hashent structure containing the key/val pair if found. If not it
//  returns the address of the pointer in which we can append the new val/pair
//  thus avoiding an unnceccessary repeated search. We can check if key was
//  found by checking whether the pointer is zero or not. This function is usually
//  used with \Ref{kiss_hash_insert_at}.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash pointer
//  @param key hash key
//  @return hash entry
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
//
//  @args  (kiss_hash_t hp, const void *key)
//  @type  struct hashent **
//  @name kiss_hash_find_hashent.
struct kiss_hashent **
kiss_hash_find_hashent(kiss_hash_t hp, const void *key)
{
    intptr_t slot = ((hp->h_keyfunc ? (*hp->h_keyfunc)(key, (hp)->h_info) :
                ((intptr_t)key + ((intptr_t)key >> 16)))  & (hp)->h_sz);

    struct kiss_hashent **pnt = hp->h_tab + slot;
    struct kiss_hashent *he;

    if (hp->h_keycmp) {
        for (he = *pnt; he != NULL; pnt = &(he->next), he = *pnt) {
            if ((*hp->h_keycmp)(he->key, key, hp->h_info) == 0) return pnt;
        }
    } else {
        for (he = *pnt; he != NULL; pnt = &(he->next), he = *pnt) {
            if (he->key == key) return pnt;
        }
    }

    return pnt;
}


//  Return address of the pointer to the value in the hash table.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash pointer
//  @param key hash key
//  @return hash entry
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
void **
kiss_hash_findaddr(kiss_hash_t hp, const void *key)
{
    struct kiss_hashent **he = kiss_hash_find_hashent(hp, key);

    if (!*he) return NULL;

    return &((*he)->val);
}


//  Insert hash element at specified position.
//  This function should be used together with \Ref{kiss_hash_find_hashent} to insert
//  the value in case it was not found at the hash.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash pointer
//  @param key hash key
//  @param key hash val
//  @return 0 - upon failure or number of hash elements after insertion in case of success.
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
int
kiss_hash_insert_at(kiss_hash_t hp, void *key, void *val, struct kiss_hashent **hloc)
{
    struct kiss_hashent *he;

    he = (struct kiss_hashent *)kiss_pmglob_memory_kmalloc(sizeof(struct kiss_hashent), "kiss_hash_insert_at");

    if (he == NULL) return 0;

    memset(he, 0, sizeof(struct kiss_hashent));

    he->key = key;
    he->val = val;
    he->next = 0;

    *hloc = he;
    hp->h_nelements++;

    if (kiss_hash_resize_check_for_resize(hp, KISS_HASH_SIZE_INCREASE) == TRUE) {
        kiss_hash_do_resize(hp, &(hp->h_resize_mode));
    }

    return hp->h_nelements;
}


//  Insert hash element.
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash pointer
//  @param key hash key
//  @param key hash val
//  @return 0 - upon failure, positive number on success.
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
int
kiss_hash_insert(kiss_hash_t hp, void *key, void *val)
{
    struct kiss_hashent **hloc = kiss_hash_find_hashent(hp, key);

    if (*hloc) {
        hent_destroy(hp, *hloc, 0);
        (*hloc)->val = val;
        (*hloc)->key = key;
        return 1;
    }

    return kiss_hash_insert_at(hp, key, val, hloc);
}


//  Lookup hash value.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash pointer
//  @param key hash key
//  @return hash value or NULL upon failure.
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
void *
kiss_hash_lookup(kiss_hash_t hp, const void *key)
{
    struct kiss_hashent **he = kiss_hash_find_hashent(hp, key);

    if (*he) return (*he)->val;

    return NULL;
}


//  Lookup hash key.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash pointer
//  @param key hash key that hash a value equal to that of the key stored in the hash.
//  @return hash key or NULL upon failure.
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
void *
kiss_hash_lookkey(kiss_hash_t hp, const void *key)
{
    struct kiss_hashent **he = kiss_hash_find_hashent(hp, key);

    if (*he) return (*he)->key;

    return NULL;
}


//  Delete hash element.
//
//  Delete hash element and return a value for the key.
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash pointer
//  @param key hash key
//  @return hash val or NULL upon failure.
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
void *
kiss_hash_delete(kiss_hash_t hp, const void *key)
{
    struct kiss_hashent **hloc = kiss_hash_find_hashent(hp, key);
    struct kiss_hashent *he = *hloc;

    if (he) {
        void *val = he->val;
        *hloc = he->next;
        hp->h_nelements--;
        hent_destroy(hp, he, 0);

        kiss_pmglob_memory_kfree(he, sizeof(struct kiss_hashent), "kiss_hash_delete");

        if (kiss_hash_resize_check_for_resize(hp, KISS_HASH_SIZE_DECREASE) == TRUE)
            kiss_hash_do_resize(hp, &(hp->h_resize_mode));

        return val;
    }

    return NULL;
}


//  Destroy hash.
//
//  If detsructor functions were defined in the call to \Ref{kiss_hash_with_create_destr} or \Ref{kiss_hash_set_destr}
//  function \Ref{kiss_hash_dodestr} must be called to enable element detsruction.
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hp hash pointer
//  @see kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//  kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete,
//  kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp
void
kiss_hash_destroy(kiss_hash_t hp)
{
    int i;
    struct kiss_hashent *he, *np;

    for (i = 0; i <= hp->h_sz; i++) {
        for (he = hp->h_tab[i]; he != NULL; he = np) {
            np = he->next;
            hent_destroy(hp, he, 1);
            kiss_pmglob_memory_kfree(he, sizeof(struct kiss_hashent), "kiss_hash_destory");
        }
    }

    if (hp->h_tab) {
        kiss_pmglob_memory_kfree(hp->h_tab, (sizeof(struct kiss_hashent *) * (hp->h_sz+1)), "kiss_hash_destroy");
    }

#ifdef HASH_DEBUG
    dbg_deregister_hash(hp);
#endif

    kiss_pmglob_memory_kfree(hp, sizeof(struct kiss_hash), "kiss_hash_destroy");
    return;
}


//    @name Hash iteration
//
//    Create hash iterator.
//
//    \begin{description}
//    \item[ MT-Level: ] Reentrant
//    \end{description}
//
//    @param hp hash
//    @return iterator object, or NULL upon failure.
//    @see kiss_hash_iterator_create, kiss_hash_iterator_next, kiss_hash_iterator_next_key, kiss_hash_iterator_destroy
kiss_hash_iterator
kiss_hash_iterator_create(kiss_hash_t hp)
{
    kiss_hash_iterator hit = (kiss_hash_iterator)kiss_pmglob_memory_kmalloc(
        sizeof (struct kiss_hash_iter),
        "kiss_hash_iterator_create"
    );

    if (hit == NULL) return NULL;

    memset(hit, 0, sizeof (struct kiss_hash_iter));

    hit->hash = hp;
    hit->slot = 0;
    hit->pntr = hit->hash->h_tab[0];

    if (!hit->pntr) kiss_hash_iterator_next_ent(hit);

    return hit;
}


//  Return next hash value.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hit hash iterator
//  @return next hash value, or NULL upon failure.
//  @see kiss_hash_iterator_create, kiss_hash_iterator_next, kiss_hash_iterator_next_key, kiss_hash_iterator_destroy
void*
kiss_hash_iterator_next(kiss_hash_iterator hit)
{
    struct kiss_hashent *hent;
    void *output;

    if (!(hent = hit->pntr)) {
        int slot = hit->slot + 1;
        struct kiss_hashent ** htab = hit->hash->h_tab;
        int sz = hit->hash->h_sz;

        while (slot <= sz && ! (hent = htab[slot])) {
            slot++;
        }

        hit->slot = slot;
        if (slot > sz) return NULL;
    }

    output = hent->val;
    hit->pntr = hent->next;

    return output;
}


//  Return next hash key.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hit hash iterator
//  @return next hash key, or NULL upon failure.
//  @see kiss_hash_iterator_create, kiss_hash_iterator_next, kiss_hash_iterator_next_key, kiss_hash_iterator_destroy
void*
kiss_hash_iterator_next_key(kiss_hash_iterator hit)
{
    struct kiss_hashent *hent;
    void *output;

    if (!(hent = hit->pntr)) {
        int slot = hit->slot + 1;
        struct kiss_hashent ** htab = hit->hash->h_tab;
        int sz = hit->hash->h_sz;

        while (slot <= sz && ! (hent=htab[slot]))
            slot++;

        hit->slot = slot;
        if (slot > sz) return NULL;
    }

    output = hent->key;
    hit->pntr = hent->next;

    return output;
}


//  Destroy hash iterator.
//
//  \begin{description}
//  \item[ MT-Level: ] Reentrant
//  \end{description}
//
//  @param hit hash iterator
//  @see kiss_hash_iterator_create, kiss_hash_iterator_next, kiss_hash_iterator_next_key, kiss_hash_iterator_destroy
void
kiss_hash_iterator_destroy (kiss_hash_iterator hit)
{
    kiss_pmglob_memory_kfree(hit, sizeof(struct kiss_hash_iter), "kiss_hash_iterator_destroy");
}


int
kiss_hash_iterator_end(kiss_hash_iterator hit)
{
    return hit->slot == -1;
}


int
kiss_hash_iterator_next_ent(kiss_hash_iterator hit)
{
    struct kiss_hashent *hent;

    if (kiss_hash_iterator_end(hit)) return 0;

    if (! hit->pntr || ! hit->pntr->next) {
        int slot = hit->slot + 1;
        struct kiss_hashent ** htab = hit->hash->h_tab;
        int sz = hit->hash->h_sz;

        while (slot <= sz && ! (hent=htab[slot])) {
            slot++;
        }

        if (slot > sz) {
            kiss_hash_iterator_set_end(hit);
            return 0;
        }
        else {
            hit->slot = slot;
            hit->pntr = hent;
        }
    }
    else {
        hit->pntr = hit->pntr->next;
    }

    return 1;
}


void *
kiss_hash_iterator_get_key(kiss_hash_iterator hit)
{
    return hit->pntr ? hit->pntr->key : NULL;
}


void *
kiss_hash_iterator_get_val(kiss_hash_iterator hit)
{
    return hit->pntr ? hit->pntr->val : NULL;
}


struct kiss_hashent *
kiss_hash_iterator_get_hashent(kiss_hash_iterator hit)
{
    return hit->pntr;
}

int
kiss_hash_iterator_equal(kiss_hash_iterator hit1, kiss_hash_iterator hit2)
{
    if (hit1->pntr || hit2->pntr) {
        return hit1->pntr == hit2->pntr;
    }
    return hit1->slot == hit2->slot && hit1->hash == hit2->hash;
}


kiss_hash_iterator
kiss_hash_iterator_copy(kiss_hash_iterator hit)
{
    kiss_hash_iterator new_hit = (kiss_hash_iterator)kiss_pmglob_memory_kmalloc(
        sizeof(struct kiss_hash_iter),
        "kiss_hash_iterator_copy"
    );
    if (hit == NULL || new_hit == NULL) return NULL;

    memset(new_hit, 0, sizeof (struct kiss_hash_iter));

    new_hit->hash = hit->hash;
    new_hit->slot = hit->slot;
    new_hit->pntr = hit->pntr;

    return new_hit;
}


void
kiss_hash_iterator_free(kiss_hash_iterator hit)
{
    if (hit) kiss_pmglob_memory_kfree(hit, sizeof(struct kiss_hash_iter), "kiss_hash_iterator_free");
}

void
kiss_hash_iterator_set_begin(kiss_hash_iterator hit)
{
    hit->slot = 0;
    hit->pntr = hit->hash->h_tab[0];

    if (!hit->pntr) kiss_hash_iterator_next_ent(hit);
}

void
kiss_hash_iterator_set_end(kiss_hash_iterator hit)
{
    hit->slot = -1;
    hit->pntr = 0;
}


kiss_hash_iterator
kiss_hash_find_hashent_new(kiss_hash_t hp, const void *key)
{
    int slot = ((hp->h_keyfunc ? (*hp->h_keyfunc)(key, (hp)->h_info) :
                ((intptr_t)key + ((intptr_t)key >> 16)))  & (hp)->h_sz);

    struct kiss_hashent *pnt = hp->h_tab[slot];

    kiss_hash_iterator iter;

    iter = kiss_hash_iterator_create(hp);

    if (hp->h_keycmp) {
        for (; pnt != NULL; pnt = pnt->next) {
            if ((*hp->h_keycmp)(pnt->key, key, hp->h_info) == 0) break;
        }
    } else {
        for (; pnt != NULL; pnt = pnt->next) {
            if (pnt->key == key) break;
        }
    }

    if (pnt == NULL) {
        kiss_hash_iterator_set_end(iter);
    } else {
        iter->slot = slot;
        iter->pntr = pnt;
    }

    return iter;
}


void
kiss_hash_delete_by_iter(kiss_hash_iterator hit)
{
    if (hit == NULL ||
        kiss_hash_iterator_end(hit) ||
        kiss_hash_iterator_get_hashent(hit) == NULL)
        return;

    kiss_hash_delete(hit->hash, kiss_hash_iterator_get_key(hit));

    return;
}

//= ==  ===   ====    =====     ======      =======       ========
//=  ==   ===    ====     =====      ======       =======
//        H a s h    r e s i z e    m e c h a n i s m
//=  ==   ===    ====     =====      ======       =======
//= ==  ===   ====    =====     ======      =======       ========


//    -----------------------------
//    KissHashResizeMode access API
//    -----------------------------
#ifdef KERNEL
#define herror      // this is done due to compilation errors after the merge from Trini to Dal
#endif

int
KissHashResizeMode_create(KissHashResizeMode **resize_mode)
{
    KissHashResizeMode *_resize_mode = NULL;

    if (!resize_mode) {
        herror(0, 0, "KissKissHashResizeMode_create: NULL resize-mode pointer");
        return -1;
    }
    _resize_mode = (KissHashResizeMode *)kiss_pmglob_memory_kmalloc(
        sizeof(KissHashResizeMode),
        "KissHashResizeMode_create"
    );

    if (!_resize_mode) {
        herror(0, 0, "KissHashResizeMode_create: Unable to allocate space for KissHashResizeMode object");
        return -1;
    }

    memset(_resize_mode, 0, sizeof(KissHashResizeMode));

    // Set default resize parameters
    KissHashResizeMode_set_default_parameters(_resize_mode);

    *resize_mode = _resize_mode;

    return 0;
}

void
KissHashResizeMode_destroy(KissHashResizeMode *resize_mode)
{
    if (!resize_mode) {
        herror(0, 0, "KissHashResizeMode_destroy: NULL resize-mode pointer");
        return;
    }
    kiss_pmglob_memory_kfree(resize_mode, sizeof(KissHashResizeMode), "KissHashResizeMode_destroy");

    return;
}

int
KissHashResizeMode_set_method(
    KissHashResizeMode *resize_mode,
    KissHashResizeMethod method,
    u_int value,
    u_int trigger_ratio
)
{
    KissHashResizeMode _resize_mode;
    int rc = 0;

    if (!resize_mode) {
        herror(0, 0, "KissHashResizeMode_set_method: NULL resize-mode pointer");
        return -1;
    }

    // set method
    _resize_mode.method = method;
    rc = KissHashResizeMode_verify_method(&_resize_mode);
    if (rc < 0) return -1;

    // set value
    _resize_mode.value = value;
    if (KissHashResizeMode_verify_value(&_resize_mode) < 0) return -1;

    // set trigger ratio
    _resize_mode.trigger_ratio = trigger_ratio;
    if (KissHashResizeMode_verify_trigger_ratio(&_resize_mode) < 0) return -1;

    resize_mode->method = method;
    resize_mode->value = value;
    resize_mode->trigger_ratio = trigger_ratio;

    return 0;
}

int
KissHashResizeMode_get_method(
    const KissHashResizeMode *resize_mode,
    KissHashResizeMethod *method,
    u_int *value,
    u_int *trigger_ratio
)
{
    if (!resize_mode || !method || !value || !trigger_ratio) {
        herror(
            0,
            0,
            "KissHashResizeMode_get_method: NULL parameter (mode=%p, method=%p, value=%p, trig=%p)",
            resize_mode,
            method,
            value,
            trigger_ratio
        );
        return -1;
    }
    *method        = resize_mode->method;
    *value         = resize_mode->value;
    *trigger_ratio = resize_mode->trigger_ratio;

    return 0;
}

int
KissHashResizeMode_set_direction(KissHashResizeMode *resize_mode, KissHashResizeDirection direction)
{
    if (!resize_mode) {
        herror(0, 0, "KissHashResizeMode_set_direction: NULL resize-mode pointer");
        return -1;
    }
    resize_mode->direction = direction;

    if (KissHashResizeMode_verify_direction(resize_mode) < 0) {
        resize_mode->direction = KISS_HASH_SIZE_INC_DEC;
        return -1;
    }

    return 0;
}

int
KissHashResizeMode_get_direction(const KissHashResizeMode *resize_mode, KissHashResizeDirection *direction)
{
    if (!resize_mode || !direction) {
        herror(
            0,
            0,
            "KissHashResizeMode_get_direction: NULL parameter (mode=%p; direction=%p)",
            resize_mode,
            direction
        );
        return -1;
    }
    *direction = resize_mode->direction;

    return 0;
}

int
KissHashResizeMode_set_max_size(KissHashResizeMode *resize_mode, u_int max_size)
{
    if (!resize_mode) {
        herror(0, 0, "KissHashResizeMode_set_max_size: NULL resize-mode pointer");
        return -1;
    }
    resize_mode->max_size = max_size;

    return 0;
}

int
KissHashResizeMode_get_max_size(const KissHashResizeMode *resize_mode, u_int *max_size)
{
    if (!resize_mode || !max_size) {
        herror(0, 0, "KissHashResizeMode_get_max_size: NULL parameter (mode=%p; max_size=%p)", resize_mode, max_size);
        return -1;
    }
    *max_size = resize_mode->max_size;

    return 0;
}

int
kiss_hash_set_resize_cb(kiss_hash_t hp, HashResizeCb_t resize_callback)
{
    if (!hp) {
        herror(0, 0, "kiss_hash_set_resize_cb: NULL hash pointer");
        return -1;
    }
    hp->h_resize_mode.cb = resize_callback;

    return 0;
}

static void
KissHashResizeMode_reset_parameters(KissHashResizeMode *resize_mode)
{
    resize_mode->max_size      = DEFAULT_KISS_HASH_SIZE;
    resize_mode->method        = KISS_HASH_RESIZE_METHOD_UNKNOWN;
    resize_mode->direction     = KISS_HASH_SIZE_STATIC;
    resize_mode->value         = 0;
    resize_mode->trigger_ratio = 0;

    return;
}

static void
KissHashResizeMode_set_default_parameters(KissHashResizeMode *resize_mode)
{
    resize_mode->max_size      = DEFAULT_KISS_HASH_SIZE;
    resize_mode->method        = KISS_HASH_RESIZE_BY_FACTOR;
    resize_mode->direction     = KISS_HASH_SIZE_INC_DEC;
    resize_mode->value         = DEFAULT_KISS_HASH_RESIZE_FACTOR_VALUE;
    resize_mode->trigger_ratio = DEFAULT_KISS_HASH_RESIZE_FACTOR_TRIG_RATIO;

    return;
}

// ------------------------------------------------------------------------
//    KissHashResizeMode parameters verification & default values function
// ------------------------------------------------------------------------
// Min & max values for a single hash resize
#define HASH_RESIZE_MIN_FACTOR_VALUE  2
#define HASH_RESIZE_MAX_FACTOR_VALUE  8
#define HASH_RESIZE_MIN_TRIG_FACTOR   2
#define HASH_RESIZE_MAX_TRIG_FACTOR   8


static int
KissHashResizeMode_verify_method(const KissHashResizeMode *resize_mode)
{
    if (resize_mode->method != KISS_HASH_RESIZE_BY_FACTOR) {
        herror(0, 0, "KissHashResizeMode_verify_method: Illegal resize method (%d)", resize_mode->method);
        return -1;
    }

    return 0;
}

static int
KissHashResizeMode_verify_value(const KissHashResizeMode *resize_mode)
{
    if (resize_mode->value == 0)
        return -1;

    if (resize_mode->method == KISS_HASH_RESIZE_BY_FACTOR) {
        if ( (resize_mode->value < HASH_RESIZE_MIN_FACTOR_VALUE) ||
            (resize_mode->value > HASH_RESIZE_MAX_FACTOR_VALUE) ) {
            herror(
                0,
                0,
                "KissHashResizeMode_verify_value: Illegal factor value (%d) - should be %d..%d",
                resize_mode->value,
                HASH_RESIZE_MIN_FACTOR_VALUE,
                HASH_RESIZE_MAX_FACTOR_VALUE
            );
            return -1;
        }
    } else {
        return -1;
    }

    return 0;
}

static int
KissHashResizeMode_verify_trigger_ratio(const KissHashResizeMode *resize_mode)
{
    if (resize_mode->method == KISS_HASH_RESIZE_BY_FACTOR) {
        if ((resize_mode->trigger_ratio < HASH_RESIZE_MIN_TRIG_FACTOR) ||
            (resize_mode->trigger_ratio > HASH_RESIZE_MAX_TRIG_FACTOR)) {
            herror(
                0,
                0,
                "KissHashResizeMode_verify_trigger_ratio: Illegal trigger value (%d) - should be %d..%d",
                resize_mode->trigger_ratio,
                HASH_RESIZE_MIN_TRIG_FACTOR,
                HASH_RESIZE_MAX_TRIG_FACTOR
            );
            return -1;
        }
    } else {
        return -1;
    }

    return 0;
}

static int
KissHashResizeMode_verify_direction(const KissHashResizeMode *resize_mode)
{
    if ((resize_mode->direction != KISS_HASH_SIZE_STATIC)   &&
        (resize_mode->direction != KISS_HASH_SIZE_INCREASE) &&
        (resize_mode->direction != KISS_HASH_SIZE_DECREASE) &&
        (resize_mode->direction != KISS_HASH_SIZE_INC_DEC) ) {
        herror(0, 0, "KissHashResizeMode_verify_direction: Illegal resize direction (%d)", resize_mode->direction);
        return -1;
    }
    return 0;
}

static int
KissHashResizeMode_verify_max_size(const kiss_hash_t hp, const KissHashResizeMode *resize_mode)
{
    if (kiss_hash_get_size(hp) > (int)resize_mode->max_size) {
        herror(
            0,
            0,
            "KissHashResizeMode_verify_max_size: Max size (%d) is lower than current hash size (%d)",
            resize_mode->max_size,
            kiss_hash_get_size(hp)
        );
        return -1;
    }
    return 0;
}

int
KissHashResizeMode_verify_params(const kiss_hash_t hp, const KissHashResizeMode *resize_mode)
{
    int rc = 0;

    if (!resize_mode) {
        herror(0, 0, "KissHashResizeMode_verify_params: NULL resize-mode pointer");
        return -1;
    }

    rc = KissHashResizeMode_verify_method(resize_mode);
    if (rc==0) rc = KissHashResizeMode_verify_value(resize_mode);
    if (rc==0) rc = KissHashResizeMode_verify_trigger_ratio(resize_mode);
    if (rc==0) rc = KissHashResizeMode_verify_direction(resize_mode);
    if (rc==0) rc = KissHashResizeMode_verify_max_size(hp, resize_mode);

    return rc;
}

// -----------------------------------
//     Set hash to have dynamic size
// -----------------------------------
int
kiss_hash_set_dynamic_size(kiss_hash_t hp, const KissHashResizeMode *resize_mode)
{
    if (!hp || !resize_mode) {
        herror(0, 0, "kiss_hash_set_dynamic_size: NULL parameter (hp=%p; mode=%p)", hp, resize_mode);
        return -1;
    }

    if (KissHashResizeMode_verify_params(hp, resize_mode) < 0) {
        herror(0, 0, "kiss_hash_set_dynamic_size: Illegal resize parameters");
        return -1;
    }

    hp->h_resize_mode.max_size      = resize_mode->max_size;
    hp->h_resize_mode.method        = resize_mode->method;
    hp->h_resize_mode.direction     = resize_mode->direction;
    hp->h_resize_mode.value         = resize_mode->value;
    hp->h_resize_mode.trigger_ratio = resize_mode->trigger_ratio;
    hp->h_resize_mode.cb            = resize_mode->cb;

    return 0;
}

int
kiss_hash_get_dynamic_size(kiss_hash_t hp, const KissHashResizeMode **resize_mode)
{
    if (!hp || !resize_mode) {
        herror(0, 0, "kiss_hash_get_dynamic_size: NULL parameter (hp=%p; mode=%p)", hp, resize_mode);
        return -1;
    }
    *resize_mode = &(hp->h_resize_mode);

    return 0;
}

// --------------------------
//   "Manual" hash resizing
// --------------------------
//
//    This API will cause an immediate resizing of hash
//    table, according to the parameters, given in the
//    input KissHashResizeMode object.
//    Note that the KissHashResizeMode object parameters are
//    not kept on the hash handle for future resize oprations.
int
kiss_hash_trigger_resize(kiss_hash_t hp, const KissHashResizeMode *resize_mode)
{
    const KissHashResizeMode *mode = resize_mode ? resize_mode : &(hp->h_resize_mode);

    if (mode->direction == KISS_HASH_SIZE_STATIC) {
        herror(0, 0, "kiss_hash_trigger_resize: Static resize mode");
        return -1;
    }

    herror(0, 0, "kiss_hash_trigger_resize: Triggering hash resize");
    return kiss_hash_do_resize(hp, mode);
}

// -----------------------
//    Resize hash table
// -----------------------
//
//    Check if resize should be triggered
static
boolean_cpt kiss_hash_resize_check_for_resize(kiss_hash_t hp, KissHashResizeDirection direction)
{
    if (!hp) return FALSE;

    // Static hash size remains fixed
    if (hp->h_resize_mode.direction == KISS_HASH_SIZE_STATIC) return FALSE;

    //
    //    Size cannot change before number of elements
    //    is larger than original hash size.
    if ((kiss_hash_get_size(hp) == kiss_hash_orig_size(hp)) && (kiss_hash_nelements(hp) < kiss_hash_orig_size(hp))) {
        return FALSE;
    }


    //    Do not expand hash with less elements than hash size.
    //    Do not shrink hash with more elements than hash size.
    if (kiss_hash_nelements(hp) < kiss_hash_get_size(hp)) {
        if ((hp->h_resize_mode.direction == KISS_HASH_SIZE_INCREASE) || (direction == KISS_HASH_SIZE_INCREASE)) {
            return FALSE;
        }
    }

    if (kiss_hash_nelements(hp) > kiss_hash_get_size(hp)) {
        if ((hp->h_resize_mode.direction == KISS_HASH_SIZE_DECREASE) || (direction == KISS_HASH_SIZE_DECREASE)) {
            return FALSE;
        }
    }


    if (hp->h_resize_mode.method == KISS_HASH_RESIZE_BY_FACTOR) {
        if (kiss_hash_nelements(hp) >= (kiss_hash_get_size(hp) * (int)hp->h_resize_mode.trigger_ratio))
            return TRUE;

        if (kiss_hash_nelements(hp) <= (kiss_hash_get_size(hp) / (int)hp->h_resize_mode.value))
            return TRUE;
    }

    return FALSE;
}


//  Calculate a new hash size for hash resizing operation.
//
//  Please note that new size is calculated differently upon
//  increase & decrease operations (refer to design doc for
//  more details).
static int
kiss_hash_resize_calc_new_size(const kiss_hash_t hp, const KissHashResizeMode *resize_mode)
{
    KissHashResizeDirection direction;
    int h_new_size = -1;

    // Determine whether to increase or decrease hash size
    if ((resize_mode->direction == KISS_HASH_SIZE_INCREASE) || (resize_mode->direction == KISS_HASH_SIZE_DECREASE)) {
        direction = resize_mode->direction;
    } else {
        if (resize_mode->direction == KISS_HASH_SIZE_INC_DEC) {
            if (kiss_hash_nelements(hp) >= kiss_hash_get_size(hp)) {
                direction = KISS_HASH_SIZE_INCREASE;
            } else {
                direction = KISS_HASH_SIZE_DECREASE;
            }
        } else {
            return -1;
        }
    }

    // Set new hash size
    if (resize_mode->method == KISS_HASH_RESIZE_BY_FACTOR) {
        if (direction == KISS_HASH_SIZE_INCREASE) {
            h_new_size = kiss_hash_get_size(hp) * resize_mode->value;
        } else {
            h_new_size = kiss_hash_get_size(hp) / resize_mode->trigger_ratio;
        }
    }
    else{
        return -1;
    }

    // Hash sizes are rounded to the nearest power of 2. Same as in hash create
    h_new_size = roundtwo(h_new_size);

    // Check that the new size does not break the allowed size limits
    if (h_new_size > (int)resize_mode->max_size) {
        herror(
            0,
            0,
            "kiss_hash_resize_calc_new_size: New size (%d) exceeds the size limit (%d)",
            h_new_size,
            resize_mode->max_size
        );
        return -1;
    }

    // Hash size cannot decrease below its original value
    if (h_new_size < kiss_hash_orig_size(hp)) {
        herror(
            0,
            0,
            "kiss_hash_resize_calc_new_size: New size (%d) is lower than the original size (%d)",
            h_new_size,
            kiss_hash_orig_size(hp)
        );
        return -1;
    }

    return h_new_size;
}


//  Hash resize function.
//  This function does the actual resize operation:
//  1. A temporary hash is created, with the new size
//  2. All elements from the original hash are inserted into the temp hash
//  3. Hash elements & size are switched between the orig & temp hash tables.
//  4. Temporary hash is destroyed.
//  returns a negative value upon failure or new hash size on success.
#define EXIT_RESIZE(msg, rc) \
    if (temp_hash)       { kiss_hash_destroy(temp_hash);} \
    if (orig_kiss_hash_iter)   {kiss_hash_iterator_free(orig_kiss_hash_iter);} \
    if (msg != nullptr)        {herror(0, 0, "kiss_hash_do_resize: %s", msg);} \
    return rc;

static int
kiss_hash_do_resize(kiss_hash_t hp, const KissHashResizeMode *resize_mode)
{
    int orig_h_sz = 0, h_new_size = 0, rc = 0;
    kiss_hash_t temp_hash = NULL;
    struct kiss_hashent **orig_h_tab  = NULL;
    kiss_hash_iterator orig_kiss_hash_iter = NULL;
    void *kiss_hash_key = NULL, *kiss_hash_val = NULL;

    if (!hp || !resize_mode) {
        EXIT_RESIZE("NULL parameter", -1);
    }
    else

    if (KissHashResizeMode_verify_params(hp, resize_mode) < 0) {
        EXIT_RESIZE("Illegal resize parameters", -1);
    }

    // Calculate new hash size
    h_new_size = kiss_hash_resize_calc_new_size(hp, resize_mode);
    if (h_new_size <= 0) {
        EXIT_RESIZE("Unable to set new hash size or hash cannot resize", -1);
    }

    //    Check that new & original hash tables do not have the same size
    //    (might happen due to the hash sizes being rounded to the nearest
    //    power of two, higher than the calculated size)
    if (h_new_size == kiss_hash_get_size(hp)) {
        EXIT_RESIZE("Original & new hash have the same size. No resize will be done.", -1);
    }

    herror(
        0,
        0,
        "kiss_hash_do_resize: Resizing hash from %d to %d (n_elements=%d)",
        kiss_hash_get_size(hp),
        h_new_size, kiss_hash_nelements(hp)
    );

    // Create a temporary hash table
    temp_hash = kiss_hash_create(h_new_size, hp->h_keyfunc, hp->h_keycmp, hp->h_info);
    if (!temp_hash) {
        EXIT_RESIZE("Unable to allocate temporary hash", -1);
    }

    // Move elements from original hash to temporary hash
    orig_kiss_hash_iter = kiss_hash_iterator_create(hp);
    if (!orig_kiss_hash_iter) {
        EXIT_RESIZE("Failed to create hash iterator", -1);
    }

    do {
        if (!(kiss_hash_iterator_get_hashent(orig_kiss_hash_iter))) continue;

        kiss_hash_key = kiss_hash_iterator_get_key(orig_kiss_hash_iter);
        kiss_hash_val = kiss_hash_iterator_get_val(orig_kiss_hash_iter);
        rc = kiss_hash_insert(temp_hash, kiss_hash_key, kiss_hash_val);
        if (!rc) {
            herror(0, 0, "kiss_hash_do_resize: Failed to add to hash (key=%x; val=%x)", kiss_hash_key, kiss_hash_val);
            EXIT_RESIZE("", -1);
        }
    } while(kiss_hash_iterator_next_ent(orig_kiss_hash_iter));

    kiss_hash_iterator_free(orig_kiss_hash_iter);
    orig_kiss_hash_iter = NULL;


    // Replace original and temporary table-pointers and sizes
    orig_h_tab       = hp->h_tab;
    orig_h_sz        = hp->h_sz;

    hp->h_tab        = temp_hash->h_tab;
    hp->h_sz         = temp_hash->h_sz;

    temp_hash->h_tab = orig_h_tab;
    temp_hash->h_sz  = orig_h_sz;

    //   Destroy temporary hash.
    //    No application data is deleted since the temporary hash
    //    has no value or key destructors, and the h_dodestr flag
    //    is not set.
    kiss_hash_destroy(temp_hash);

    // Notify application on hash resize
    if (resize_mode->cb) resize_mode->cb(hp, hp->h_info);

    return kiss_hash_get_size(hp);
}
#undef EXIT_RESIZE


//  Hashing fuction for string hash.
//  This function is used by hash_strcreate().
//  @param vs key
//  @param info opaque
//  @return value of the hash function.
uintptr_t
kiss_hash_strvalue(const void *vs, CP_MAYBE_UNUSED void *info)
{
    unsigned int val;
    const char* s = (const char *)vs;

    for(val = 0; *s; s++) {
        val = ((val >> 3) ^ (val<<5)) + *s;
    }
    return val;
}


//  Comparison fuction for string hash.
//  This function is used by hash_strcreate().
//
//  @param vk1 key
//  @param vk2 key
//  @param info opaque
//  @return 0 - keys are equal, otherwise different.
int
kiss_hash_strcmp(const void* vk1, const void* vk2, CP_MAYBE_UNUSED void *info)
{
    const char* k1 = (const char *)vk1;
    const char* k2 = (const char *)vk2;
    return strcmp(k1, k2);
}


//  Hashing fuction for integer hash.
//  This function is used by hash_intcreate().
//  @param v key
//  @param info opaque
//  @return value of the hash function.
uintptr_t
kiss_hash_intvalue(const void* v, CP_MAYBE_UNUSED void *info)
{
    return (uintptr_t)v;
}


//  Comparison fuction for integer hash.
//  This function is used by hash_intcreate().
//
//  @param vv1 key
//  @param vv2 key
//  @param info opaque
//  @return 0 - keys are equal, otherwise different.
int
kiss_hash_intcmp(const void* vv1, const void* vv2, CP_MAYBE_UNUSED void *info)
{
    intptr_t v1 = (intptr_t)vv1;
    intptr_t v2 = (intptr_t)vv2;
    return v1 - v2;
}


#ifdef KERNEL
#undef herror
#endif
