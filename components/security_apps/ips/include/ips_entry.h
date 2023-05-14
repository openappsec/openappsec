#ifndef __IPS_ENTRY_H__
#define __IPS_ENTRY_H__

#include <map>
#include <set>

#include "table_opaque.h"
#include "parsed_context.h"
#include "buffer.h"
#include "context.h"

class IPSEntry : public TableOpaqueSerialize<IPSEntry>, public Listener<ParsedContext>
{
public:
    IPSEntry();

    void upon(const ParsedContext &) override;
    ParsedContextReply respond(const ParsedContext &ctx) override;
    std::string getListenerName() const override { return name(); }

    template <typename T>
    void serialize(T &, uint32_t) {}
    static std::string name();
    static std::unique_ptr<TableOpaqueBase> prototype();
    static uint currVer();
    static uint minVer();

    void uponEnteringContext() override { registerListener(); }
    void uponLeavingContext() override { unregisterListener(); }

    void setFlag(const std::string &flag) { flags.insert(flag); }
    void unsetFlag(const std::string &flag) { flags.erase(flag); }
    bool isFlagSet(const std::string &flag) const { return flags.count(flag) != 0; }

    Buffer getBuffer(const std::string &name) const;
    void setTransactionData(const Buffer &key, const Buffer &value);
    Maybe<Buffer> getTransactionData(const Buffer &key) const;

    void addPendingContext(const std::string &name, const Buffer &buffer);
    const std::vector<std::pair<std::string, Buffer>> getPendingContexts() const { return pending_contexts; }
    void clearPendingContexts() { pending_contexts.clear(); }

    void setDrop() { is_drop = true; }
    bool isDrop() const { return is_drop; }

private:
    std::map<std::string, Buffer> past_contexts;
    std::set<std::string> flags;
    Context ctx;
    std::map<Buffer, Buffer> transaction_data;
    std::vector<std::pair<std::string, Buffer>> pending_contexts;

    bool is_drop = false;
};

#endif // __IPS_ENTRY_H__
