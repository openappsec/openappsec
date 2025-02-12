#ifndef __REQUESTS_MONITOR_H__
#define __REQUESTS_MONITOR_H__
#include "i_serialize.h"

typedef std::map<uint64_t, std::map<std::string, size_t>> MonitorData;

class SourcesRequestMonitor : public SerializeToLocalAndRemoteSyncBase
{
public:
    SourcesRequestMonitor(
        const std::string& filePath,
        const std::string& remotePath,
        const std::string& assetId,
        const std::string& owner);
    virtual ~SourcesRequestMonitor();
    virtual void syncWorker() override;
    void logSourceHit(const std::string& source);
protected:
    virtual void pullData(const std::vector<std::string> &data) override;
    virtual void processData() override;
    virtual void postProcessedData() override;
    virtual void pullProcessedData(const std::vector<std::string> &data) override;
    virtual void updateState(const std::vector<std::string> &data) override;
    virtual bool postData() override;

    void serialize(std::ostream& stream);
    void deserialize(std::istream& stream);
private:
    // map of sources and their requests per minute (UNIX)
    MonitorData m_sourcesRequests;
};

#endif // __REQUESTS_MONITOR_H__
