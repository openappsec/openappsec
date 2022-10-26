// Copyright 2021, Hubert Jagodziński
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

// C Mock - Google Mock's extension allowing a function mocking.
//
// This file implements helper macros for internal use only.

#ifndef CMOCK_INCLUDE_CMOCK_CMOCK_INTERNAL_H_
#define CMOCK_INCLUDE_CMOCK_CMOCK_INTERNAL_H_

#define CMOCK_INTERNAL_NO_PARAMETER_NAME(_i, _Signature, _) \
    GMOCK_PP_COMMA_IF(_i) \
    GMOCK_INTERNAL_ARG_O(_i, GMOCK_PP_REMOVE_PARENS(_Signature))

#define CMOCK_INTERNAL_RETURN_TYPE(_Signature) \
    typename ::testing::internal::Function<GMOCK_PP_REMOVE_PARENS(_Signature)>::Result

#endif // CMOCK_INCLUDE_CMOCK_CMOCK_INTERNAL_H_