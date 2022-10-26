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

#ifndef __KISS_HASH_H__
#define __KISS_HASH_H__

#include "general_adaptor.h"

typedef struct kiss_hash *kiss_hash_t;

struct kiss_hashent {
    void *key;
    void *val;
    struct kiss_hashent *next;
};

typedef uintptr_t (*hkeyfunc_t)(const void *key, void *info);
typedef int (*hcmpfunc_t)(const void *key1, const void *key2, void *info);
typedef void (*freefunc_t)(void *info);

// {group: API for KISS_HASH}
#define H_DESTR(destr, addr) \
if (destr && (((uintptr_t)(addr)) > 0x10)) (*destr)(addr);

// {group: API for KISS_HASH}
// Description: Create Hash Table.                MT-Level: Reentrant
//    Parameters:
//        hsize - hash size
//        keyfunc - key hashing function
//        keycmp - key comparison function
//        info - opaque for use of keyfunc and keycmp functions.
//    Return values:
//        o hash pointer
//        o NULL upon failure
//    See also: kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//        kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert,
//        kiss_hash_delete, kiss_hash_destroy, kiss_hash_find_kiss_hashent, kiss_hash_insert_at, kiss_hash_strvalue,
//        kiss_hash_strcmp,  kiss_hash_intvalue, kiss_hash_bytevalue,
//        kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
kiss_hash_t kiss_hash_create (size_t hsize, hkeyfunc_t keyfunc, hcmpfunc_t keycmp, void *info);

// {group: API for HASH}
// Description: Create Hash Table with Destructor.            MT-Level: Reentrant
//    Parameters:
//        hsize - hash size
//        keyfunc - key hashing function
//        keycmp - key comparison function
//        val_destr - destructor for the values of the hash
//        key_destr - destructor for the keys of the hash
//        info - opaque for use of keyfunc and  keycmp functions.
//    Return values:
//        o hash pointer
//        o NULL upon failure
//    See also: kiss_hash_create, kiss_hash_set_destr, kiss_hash_dodestr, kiss_hash_undo_destr, kiss_hash_nelements,
//       iss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert, kiss_hash_delete, kiss_hash_destroy,
//       kiss_hash_find_kiss_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,  kiss_hash_intvalue,
//       kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
kiss_hash_t
kiss_hash_create_with_destr (
    size_t hsize,
    hkeyfunc_t keyfunc,
    hcmpfunc_t keycmp,
    freefunc_t val_destr,
    freefunc_t key_destr,
    void *info
);

#define kiss_hash_create(hsize, hkeyfunc, hcmpfunc, info) \
    _kiss_hash_create (hsize, hkeyfunc, hcmpfunc, info, __FILE__, __LINE__)

#define kiss_hash_create_with_destr(hsize, hkeyfunc, hcmpfunc, freefunc1, freefunc2, info) \
    _kiss_hash_create_with_destr (hsize, hkeyfunc, hcmpfunc, freefunc1, freefunc2, info, __FILE__, __LINE__)

kiss_hash_t
_kiss_hash_create_with_ksleep(size_t hsize, hkeyfunc_t, hcmpfunc_t,  void *info, const char *file, int line);

#define kiss_hash_create_with_ksleep(hsize, hkeyfunc, hcmpfunc, info) \
    _kiss_hash_create_with_ksleep (hsize, hkeyfunc, hcmpfunc, info, __FILE__, __LINE__)


// {group: API for HASH}
// Description: Debug single hash.                MT-Level: Reentrant
//This function calculates and prints the following statistics:
//o hash pointer
//o file name and line number where kiss_hash_create or kiss_hash_create_with_destr was called
//o number of elements in kiss_hash
//o number of slots in hash - hash size
//o size in bytes of memory occupied by hash maintenance structures
//o slot utilzation - percentage of hash slots used to store elements
//o average number of lookups - average length of lists of elements
//    Parameters:
//        hash - pointer to hash
//    Return values:
//        size in bytes of memory occupied by hash maintenance structures.
//    See also: hash_create, hash_create_with_destr, hash_set_destr, hash_dodestr, hash_undo_destr,
//        hash_nelements, hash_findaddr, hash_lookup, hash_lookkey, hash_insert, hash_delete, hash_destroy,
//        hash_find_hashent, hash_insert_at, hash_strvalue, hash_strcmp,  hash_intvalue, hash_bytevalue,
//        hash_bytecmp, hash_debug_all
int kiss_hash_debug(kiss_hash_t hp);

// {group: API for HASH}
// Description: Debug single hash.                MT-Level: Safe
//Iterates a list of all hash tables craeted in the current process and
//for each hash calls function hash_debug. In addition the total
//memory usage of hash maintenance structures is printed.
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey,
//        kiss_hash_insert, kiss_hash_delete, kiss_hash_destroy,
//        kiss_hash_find_kiss_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,  kiss_hash_intvalue,
//        kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug
void kiss_hash_debug_all();

// {group: API for kiss_hash}
kiss_hash_t _kiss_hash_create (size_t hsize, hkeyfunc_t, hcmpfunc_t,  void *info, const char *file, int line);

//  {group: API for HASH}
kiss_hash_t _kiss_hash_create_with_destr (size_t hsize, hkeyfunc_t, hcmpfunc_t, freefunc_t, freefunc_t,
                void *info, const char *file, int line);

// {group: API for HASH}
// Description: Set destructor for hash elements.            MT-Level: ] Reentrant
//Keys and values detsructors are called for every hash key-value pair when the hash is destroyed.
//    Parameters:
//        hp - hash
//        val_destr - destructor for the values of the hash
//        key_destr - destructor for the keys of the hash
//    Return values:
//        hash pointer
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_dodestr, kiss_hash_undo_destr,
//        kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert,
//        kiss_hash_delete, kiss_hash_destroy, kiss_hash_find_kiss_hashent, kiss_hash_insert_at, kiss_hash_strvalue,
//        kiss_hash_strcmp,  kiss_hash_intvalue, kiss_hash_bytevalue,
//        kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
kiss_hash_t kiss_hash_set_destr (kiss_hash_t hp, freefunc_t val_destr, freefunc_t key_destr);

// {group: API for kiss_hash}
// Description: Enable hash element detsruction.            MT-Level: Reentrant
//Hash is created with destruction of elements disabled by default.
//This function enables destruction upon a call to kiss_hash_destroy.
//Meaning, the hash will automaticly call destructors when an entry gets
//deleted from the hash. Usualy this is not the case !
//    Parameters:
//        hp - hash
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_undo_destr,
//        kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert,
//        kiss_hash_delete, kiss_hash_destroy, kiss_hash_find_kiss_hashent, kiss_hash_insert_at, kiss_hash_strvalue,
//       kiss_hash_strcmp,  kiss_hash_intvalue, kiss_hash_bytevalue,
//        kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
void kiss_hash_dodestr (kiss_hash_t hp);

// {group: API for HASH}
// Description: Disable hash element detsruction.            MT-Level: Reentrant
//    Parameters:
//        hp - hash
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert,
//        kiss_hash_delete, kiss_hash_destroy,
//        kiss_hash_find_kiss_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,  kiss_hash_intvalue,
//        kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
void kiss_hash_undo_destr (kiss_hash_t hp);

// {group: API for HASH}
// Description: Number of hash elements.                MT-Level: Reentrant
//    Parameters:
//        hash - hash table
//    Return values:
//        number of elements
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert,
//        kiss_hash_delete, kiss_hash_destroy,
//        kiss_hash_find_kiss_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,  kiss_hash_intvalue,
//        kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_kiss_hash_debug, kiss_hash_debug_all
int kiss_hash_nelements (kiss_hash_t hash);

// {group: API for HASH}
// Description: Hash size.                MT-Level: Reentrant
//    Parameters:
//        hash - hash table
//    Return values:
//        Size of hash
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey,
//        kiss_hash_insert, kiss_hash_delete, kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at,
//        kiss_hash_strvalue, kiss_hash_strcmp,  kiss_hash_intvalue, kiss_hash_bytevalue,
//        kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
int kiss_hash_get_size (kiss_hash_t hash);

//  {group: API for HASH}
//  Description: Return address of the pointer to the value in the hash table.
//    Parameters:
//        hp - hash pointer
//        key - hash key
//    Return values:
//        hash entry
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_lookup, kiss_hash_lookkey, kiss_hash_insert,
//        kiss_hash_delete, kiss_hash_destroy,
//        kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,  kiss_hash_intvalue,
//        kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
void **kiss_hash_findaddr (kiss_hash_t hp, const void *key);

//  {group: API for HASH}
//  Description: Lookup hash value.                MT-Level: Reentrant
//    Parameters:
//        hp - hash pointer
//        key - hash key
//    Return values:
//        o hash value
//        o NULL upon failure
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookkey, kiss_hash_insert,
//        kiss_hash_delete, kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue,
//        kiss_hash_strcmp,  kiss_hash_intvalue, kiss_hash_bytevalue,
//        kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
void *kiss_hash_lookup (kiss_hash_t hp, const void *key);

//  {group: API for HASH}
//  Description: Lookup hash key.                MT-Level: Reentrant
//Returns the key pointer as stored in the hash table.
//    Parameters:
//        hp - hash pointer
//        key - hash key that hash a value equal to that of the key stored in the hash.
//    Return values:
//        o hash key
//        o NULL upon failure
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_insert,
//        kiss_hash_delete, kiss_hash_destroy,kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue,
//        kiss_hash_strcmp, kiss_hash_intvalue, kiss_hash_bytevalue,
//        kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
void *kiss_hash_lookkey (kiss_hash_t hp, const void *key);

//  {group: API for HASH}
//  Description: Insert hash element.                MT-Level: Reentrant
//    Parameters:
//        hp - hash pointer
//        key - hash key
//        val - hash val
//    Return values:
//        >0 - success
//        0 - upon failure
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey,
//        kiss_hash_delete, kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue,
//        kiss_hash_strcmp,  kiss_hash_intvalue, kiss_hash_bytevalue,
//        kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
int kiss_hash_insert (kiss_hash_t hp, void *key, void *val);

//  {group: API for HASH}
//  Description: Delete hash element.                MT-Level: Reentrant
//Delete hash element and return a value for the key.
//    Parameters:
//        hp - hash pointer
//        key - hash key
//    Return values:
//        o hash val
//        o NULL upon failure
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey,
//        kiss_hash_insert, kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue,
//        kiss_hash_strcmp,  kiss_hash_intvalue, kiss_hash_bytevalue,
//        kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
void *kiss_hash_delete (kiss_hash_t hash, const void *key);

//  {group: API for HASH}
//  Description: Destroy hash.                   MT-Level: Reentrant
//If detsructor functions were defined in the call to kiss_hash_with_create_destr or kiss_hash_set_destr
//function kiss_hash_dodestr must be called to enable element detsruction.
//    Parameters:
//        hp - hash pointer
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr,kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey,
//        kiss_hash_insert, kiss_hash_delete, kiss_hash_find_hashent, kiss_hash_insert_at, kiss_hash_strvalue,
//        kiss_hash_strcmp,  kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug,
//        kiss_hash_debug_all
void kiss_hash_destroy (kiss_hash_t hp);

//  {group: API for HASH}
//  Description: Find hash entry.                MT-Level: Reentrant
//Used as an efficient but somewhat ugly interface for find/insert operation.
//What it does is to return an adrress of a pointer to a hashent structure containing the key/val pair if found.
//If not it returns the address of the pointer in which we can append the new val/pair
//thus avoiding an unnceccessary repeated search.
//We can check if key was found by checking whether the pointer is zero or not.
//This function is usually used with kiss_hash_insert_at.
//    Parameters:
//        hp - hash pointer
//        key - hash key
//    Return values:
//        hash entry
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//    kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey,
//    kiss_hash_insert, kiss_hash_delete, kiss_hash_destroy, kiss_hash_insert_at, kiss_hash_strvalue, kiss_hash_strcmp,
//    kiss_hash_intvalue, kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
struct kiss_hashent ** kiss_hash_find_hashent(kiss_hash_t hp, const void *key);

//  {group: API for HASH}
//  Description: Insert hash element at specified position.        MT-Level: Reentrant
//This function should be used together with kiss_hash_find_hashent to insert
//the value in case it was not found at the hash.
//    Parameters:
//        hp - hash pointer
//        key - hash key
//        val - hash val
//        hloc -
//    Return values:
//        o 0 upon failure
//        o number of hash elements after insertion in case of success.
//    See also: kiss_hash_create, kiss_hash_create_with_destr, kiss_hash_set_destr, kiss_hash_dodestr,
//        kiss_hash_undo_destr, kiss_hash_nelements, kiss_hash_findaddr, kiss_hash_lookup, kiss_hash_lookkey,
//        kiss_hash_insert, kiss_hash_delete,
//        kiss_hash_destroy, kiss_hash_find_hashent, kiss_hash_strvalue, kiss_hash_strcmp,  kiss_hash_intvalue,
//        kiss_hash_bytevalue, kiss_hash_bytecmp, kiss_hash_debug, kiss_hash_debug_all
int kiss_hash_insert_at (kiss_hash_t hp, void *key, void *val, struct kiss_hashent**hloc);


#define kiss_hash_strcreate(sz) \
    kiss_hash_create(sz, (hkeyfunc_t)kiss_hash_strvalue, (hcmpfunc_t)kiss_hash_strcmp, NULL)

#define kiss_hash_intcreate(sz) \
    kiss_hash_create(sz, (hkeyfunc_t)kiss_hash_intvalue, (hcmpfunc_t)kiss_hash_intcmp, NULL)

#define kiss_hash_bytecreate(n, esz) \
    kiss_hash_create(n, (hkeyfunc_t)kiss_hash_bytevalue, (hcmpfunc_t)kiss_hash_bytecmp, (void *)esz)

// The following provide hash table data type interface,
// These functions can be provided by the user,
// The default provided functions provide string hash

//  {group: API for HASH}
//  Description: Hashing fuction for string hash.
//This function is used by kiss_hash_strcreate().
//    Parameters:
//        vs - key
//        info - opaque
//    Return values:
//        value of the hash function.
uintptr_t kiss_hash_strvalue (const void *vs, void *info);

//  {group: API for HASH}
//  Description: Comparison fuction for string hash.
//This function is used by kiss_hash_strcreate().
//    Parameters:
//        vk1 - key
//        vk2 - key
//        info - opaque
//    Return values:
//        0 - keys are equal
//        !0 - keys are different
int kiss_hash_strcmp (const void *vk1, const void *vk2, void *info);

//  {group: API for HASH}
//  Description: Hashing fuction for integer hash.
//This function is used by kiss_hash_intcreate().
//    Parameters:
//        v - key
//        info - opaque
//    Return values:
//        value of the hash function.
uintptr_t kiss_hash_intvalue (const void* v, void *info);

//  {group: API for HASH}
//  Description: Comparison fuction for integer hash.
//This function is used by kiss_hash_intcreate().
//    Parameters:
//        vv1 - key
//        vv2 - key
//        info - opaque
//    Return values:
//        0 - keys are equal
//        !0 - keys are different
int kiss_hash_intcmp (const void* vv1, const void* vv2, void *info);

//  {group: API for HASH}
//  Description: Hashing fuction for byte hash.
//This function is used by kiss_hash_bytecreate().
//    Parameters:
//        data - key
//        info - opaque
//    Return values:
//        value of the hash function.
uintptr_t kiss_hash_bytevalue (const void *data, void *info);

//  {group: API for HASH}
//  Description: Comparison fuction for byte hash.
//This function is used by kiss_hash_bytecreate().
//    Parameters:
//        d1 - key
//        d2 - key
//        info - opaque
//    Return values:
//        0 - keys are equal
//        !0 - keys are different
int kiss_hash_bytecmp (const void *d1, const void *d2, void *info);

// {group: API for HASH ITERATOR}
typedef struct kiss_hash_iter *kiss_hash_iterator;

// {group: API for HASH ITERATOR}
//  Description: Create hash iterator.                MT-Level: Reentrant
//    Parameters:
//        hp - hash
//    Return values:
//        o iterator object
//        o NULL upon failure
//    See also:
//       kiss_hash_iterator_next, kiss_hash_iterator_next_key, kiss_hash_iterator_destroy
kiss_hash_iterator kiss_hash_iterator_create (kiss_hash_t hp);

// {group: API for HASH ITERATOR}
//  Description: Return next hash value.            MT-Level: Reentrant
//    Parameters:
//        hit - hash iterator
//    Return values:
//        o next hash value
//        o NULL upon failure
//    See also:
//        kiss_hash_iterator_create, kiss_hash_iterator_next_key, kiss_hash_iterator_destroy
void *kiss_hash_iterator_next (kiss_hash_iterator hit);

// {group: API for HASH ITERATOR}
// Description: Return next hash key.                MT-Level: Reentrant
//    Parameters:
//        hit - hash iterator
//    Return values:
//       o next hash key
//        o NULL upon failure
//    See also:
//        kiss_hash_iterator_create, kiss_hash_iterator_next, kiss_hash_iterator_destroy
void *kiss_hash_iterator_next_key (kiss_hash_iterator hit);

// {group: API for HASH ITERATOR}
// Description: Destroy hash iterator.                MT-Level: Reentrant
//   Parameters:
//        hit - hash iterator
//    See also:
//        kiss_hash_iterator_create, kiss_hash_iterator_next, kiss_hash_iterator_next_key
void kiss_hash_iterator_destroy (kiss_hash_iterator hit);

//  {group: API for ITERATOR}
int kiss_hash_iterator_next_ent(kiss_hash_iterator hit);

//  {group: API for ITERATOR}
void * kiss_hash_iterator_get_key(kiss_hash_iterator hit);

//  {group: API for ITERATOR}
void * kiss_hash_iterator_get_val(kiss_hash_iterator hit);

//  {group: API for ITERATOR}
struct kiss_hashent * kiss_hash_iterator_get_hashent(kiss_hash_iterator hit);

//  {group: API for ITERATOR}
int kiss_hash_iterator_equal(kiss_hash_iterator hit1, kiss_hash_iterator hit2);

//  {group: API for ITERATOR}
kiss_hash_iterator kiss_hash_iterator_copy(kiss_hash_iterator hit);

//  {group: API for ITERATOR}
void kiss_hash_iterator_free(kiss_hash_iterator hit);

//  {group: API for ITERATOR}
void kiss_hash_iterator_set_begin(kiss_hash_iterator hit);

//  {group: API for ITERATOR}
void kiss_hash_iterator_set_end(kiss_hash_iterator hit);

//  {group: API for HASH}
kiss_hash_iterator kiss_hash_find_hashent_new(kiss_hash_t hp, const void *key);

// {group: API for HASH ITERATOR}
void kiss_hash_delete_by_iter(kiss_hash_iterator hit);

//    - - - - - - - - - - - - - - -
//       Hash resize mechanism
//    - - - - - - - - - - - - - - -

// {group: API for HASH RESIZE}
// Determine if hash size can increase, decrease or both.
typedef enum {
    KISS_HASH_SIZE_STATIC    = 0,    // hash size is kept fixed
    KISS_HASH_SIZE_INCREASE  = 1,
    KISS_HASH_SIZE_DECREASE  = 2,
    KISS_HASH_SIZE_INC_DEC   = 3
} KissHashResizeDirection;

// {group: API for HASH RESIZE}
typedef enum {
    KISS_HASH_RESIZE_METHOD_UNKNOWN = 0,
    KISS_HASH_RESIZE_BY_FACTOR      = 1
} KissHashResizeMethod;

// {group: API for HASH RESIZE}
// Default maximal hash size:
// Hash size will not increase beyond this value unless stated o/w by the application
#define DEFAULT_KISS_HASH_SIZE       (1<<17)

// {group: API for HASH RESIZE}
// Default value for hash factorial resizing
#define DEFAULT_KISS_HASH_RESIZE_FACTOR_VALUE        4
// {group: API for HASH RESIZE}
// Default value for hash factorial resizing trigger ratio
#define DEFAULT_KISS_HASH_RESIZE_FACTOR_TRIG_RATIO   2

// {group: API for HASH RESIZE}
// Resize application callback: This callback will be invoked at every successful resize operation.
typedef int (* HashResizeCb_t) (kiss_hash_t hp, void *app_info);


//   Hash resize mode object & accsess API.
//   Used for setting resize parameters hash.

// {group: API for HASH RESIZE}
typedef struct _KissHashResizeMode KissHashResizeMode;

//  {group: API for HASH RESIZE}
int  KissHashResizeMode_create(KissHashResizeMode **resize_mode);

//  {group: API for HASH RESIZE}
void KissHashResizeMode_destroy(KissHashResizeMode *resize_mode);

//  {group: API for HASH RESIZE}
int KissHashResizeMode_set_method(
    KissHashResizeMode *resize_mode,
    KissHashResizeMethod  method,
    u_int value,
    u_int trigger_ratio);

//  {group: API for HASH RESIZE}
int KissHashResizeMode_get_method(
    const KissHashResizeMode *resize_mode,
    KissHashResizeMethod *method,
    u_int *value,
    u_int *trigger_ratio);

// {group: API for HASH RESIZE}
int  KissHashResizeMode_set_direction(KissHashResizeMode *resize_mode, KissHashResizeDirection direction);

// {group: API for HASH RESIZE}
int  KissHashResizeMode_get_direction(const KissHashResizeMode *resize_mode, KissHashResizeDirection *direction);

// {group: API for HASH RESIZE}
int  KissHashResizeMode_set_max_size(KissHashResizeMode *resize_mode, u_int max_size);

// {group: API for HASH RESIZE}
int  KissHashResizeMode_get_max_size(const KissHashResizeMode *resize_mode, u_int *max_size);

// {group: API for HASH RESIZE}
int  kiss_hash_set_resize_cb(kiss_hash_t hp, HashResizeCb_t resize_callback);

// {group: API for HASH RESIZE}
// Description: Set hash dynamic size parameters.
//    Parameters:
//        hp - [in] pointer to hash table
//        resize_mode - [in] should be created and set using the access API to the KissHashResizeMode object.
//                        After using the set API, this object can be destroyed.
//
int kiss_hash_set_dynamic_size(kiss_hash_t hp, const KissHashResizeMode *resize_mode);

// {group: API for HASH RESIZE}
// Description: Get hash dynamic size parameters.
//    Parameters:
//        hp - [in] pointer to hash table
//        resize_mode - [out] a read-only parameter that should not be changed by the application.
int kiss_hash_get_dynamic_size(kiss_hash_t hp, const KissHashResizeMode **resize_mode);

// {group: API for HASH RESIZE}
//  Description: This API will cause an immediate resizing of hash
//     table, according to the parameters, given in the input
//     KissHashResizeMode object (if NULL, the resize will be done
//     according to the parameters as last set by the application).
//
//     Note that the KissHashResizeMode object parameters are
//     not kept on the hash handle for future resize oprations.
int kiss_hash_trigger_resize(kiss_hash_t hp, const KissHashResizeMode *resize_mode);

#endif // __KISS_HASH_H__
