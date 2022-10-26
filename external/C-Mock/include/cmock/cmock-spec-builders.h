// Copyright 2013, Hubert Jagodziński
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Author: hubert.jagodzinski@gmail.com (Hubert Jagodziński)

// C Mock - extension to Google Mock framework allowing for writing C mock functions.
//
// This file implements the ON_FUNCTION_CALL() and EXPECT_FUNCTION_CALL() macros.

#ifndef CMOCK_INCLUDE_CMOCK_CMOCK_SPEC_BUILDERS_H_
#define CMOCK_INCLUDE_CMOCK_CMOCK_SPEC_BUILDERS_H_

#define CMOCK_ON_FUNCTION_CALL_IMPL_(obj, call) \
    ((obj).cmock_func call).InternalDefaultActionSetAt(__FILE__, __LINE__, \
                                                    #obj, #call)
#define ON_FUNCTION_CALL(obj, call) CMOCK_ON_FUNCTION_CALL_IMPL_(obj, call)

#define CMOCK_EXPECT_FUNCTION_CALL_IMPL_(obj, call) \
    ((obj).cmock_func call).InternalExpectedAt(__FILE__, __LINE__, #obj, #call)
#define EXPECT_FUNCTION_CALL(obj, call) CMOCK_EXPECT_FUNCTION_CALL_IMPL_(obj, call)

#endif // CMOCK_INCLUDE_CMOCK_CMOCK_SPEC_BUILDERS_H_
