// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0
// See LICENSE file in the project root for full license information.

#ifndef __KEY_WRAPPER_H__
#define __KEY_WRAPPER_H__

#include <memory>
#include "context.h"
#include "debug.h"

USE_DEBUG_FLAG(D_TABLE);

class KeyWrapper {
public:
    template <typename TableKey>
    void set(const TableKey& key) {
        dbgTrace(D_TABLE) << "Setting key: " << key;
        key_value = std::make_unique<Context::Value<TableKey>>([key]() { return Context::Return<TableKey>(key); });
    }

    template <typename TableKey>
    bool get(TableKey& out) const {
        if (!key_value) return false;
        dbgTrace(D_TABLE) << "Getting key of type: " << typeid(TableKey).name();
        return key_value->extractTo(&out, typeid(TableKey));
    }

    void clear() { key_value.reset(); }
    bool hasValue() const { return key_value != nullptr; }

private:
    std::unique_ptr<Context::AbstractValue> key_value;
};

#endif // __KEY_WRAPPER_H__
