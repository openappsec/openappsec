#include "unified_learning_comp.h"
#include <chrono>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include "AssetIndicatorsSyncUnit.h"
#include "UnifiedIndicatorsContainer.h"
#include "debug.h"
#include "hiredis/hiredis.h"
#include "i_mainloop.h"
#include "i_time_get.h"
#include "i_unified_learning.h"
#include "singleton.h"

USE_DEBUG_FLAG(D_UNIFIED_LEARNING);

// Business logic class that orchestrates Redis processing and per-asset synchronization
class UnifiedLearningManager
{
public:
    UnifiedLearningManager() :
        sync_interval(std::chrono::minutes(120)),
        wait_for_sync(std::chrono::seconds(300)),
        redis_port(0),
        redis_timeout_usec(0),
        queue_discovery_interval_msec(0),
        m_unified_learning_enabled(false)
    {}

    void
    init()
    {
        dbgTrace(D_UNIFIED_LEARNING) << "Starting Redis-based Unified Learning Manager (Asset-based)";

        mainloop = Singleton::Consume<I_MainLoop>::by<UnifiedLearningComponent>();
        i_time_get = Singleton::Consume<I_TimeGet>::by<UnifiedLearningComponent>();
        agentDetails = Singleton::Consume<I_AgentDetails>::by<UnifiedLearningComponent>();
        
        m_tenant_id = agentDetails->getTenantId();
        redis_host = getConfigurationWithDefault<std::string>("127.0.0.1", "connection", "Redis IP");
        redis_port = getConfigurationWithDefault<int>(6379, "connection", "Redis Port");
        redis_timeout_usec = getConfigurationWithDefault<int>(30000, "connection", "Redis Timeout");
        queue_discovery_interval_msec =
            getConfigurationWithDefault<int>(30000, "connection", "Queue Discovery Interval");

        // Initialize with policy-driven Redis connection
        mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [this]() {
                handleNewPolicy();
                registerConfigLoadCb([this]() { handleNewPolicy(); });
            },
            "Initialize unified learning component",
            true
        );

        dbgTrace(D_UNIFIED_LEARNING) << "Redis-based Unified Learning Manager initialized (Asset-based mode)";
    }

    void
    fini()
    {
        dbgTrace(D_UNIFIED_LEARNING) << "Shutting down Unified Learning Manager";

        // Stop processing routine
        stopRedisProcessingRoutine();

        // Save all asset sync units before shutdown
        saveAndClearAssetSyncUnits();
        disconnectRedis();

        dbgTrace(D_UNIFIED_LEARNING) << "Unified Learning Manager shutdown complete";
    }

private:


    bool
    connectRedis()
    {
        disconnectRedis();

        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = redis_timeout_usec;

        redisContext *context = redisConnectWithTimeout(redis_host.c_str(), redis_port, timeout);
        if (context != nullptr && context->err) {

            dbgWarning(D_UNIFIED_LEARNING)
                << "Error connecting to Redis: "
                << context->errstr;

            redisFree(context);
            return false;
        }

        if (context == nullptr) {
            dbgWarning(D_UNIFIED_LEARNING) << "Failed to create Redis context";
            return false;
        }

        redis = context;

        // Set Redis memory limit to 512MB
        redisReply *configReply =
            static_cast<redisReply *>(redisCommand(redis, "CONFIG SET maxmemory 536870912")); // 512MB in bytes
        if (configReply) {
            freeReplyObject(configReply);
        }

        // Set eviction policy to remove oldest entries when memory limit reached
        configReply = static_cast<redisReply *>(redisCommand(redis, "CONFIG SET maxmemory-policy allkeys-lru"));
        if (configReply) {
            freeReplyObject(configReply);
        }

        // Load Lua script for batch processing
        static std::string luaScript = R"(
            local listKey = KEYS[1]
            local batchSize = tonumber(ARGV[1])
            local entries = {}
            for i = 1, batchSize do
                local entry = redis.call('LPOP', listKey)
                if entry == false then break; end
                table.insert(entries, entry)
            end
            return entries
        )";

        redisReply *loadReply = static_cast<redisReply *>(redisCommand(redis, "SCRIPT LOAD %s", luaScript.c_str()));
        if (loadReply && loadReply->type == REDIS_REPLY_STRING) {
            lua_script_hash = loadReply->str;
            freeReplyObject(loadReply);
        }

        dbgTrace(D_UNIFIED_LEARNING) << "Successfully connected to Redis with 512MB memory limit";
        return true;
    }

    void
    reconnectRedis()
    {
        if (!is_reconnecting) {
            is_reconnecting = true;
            mainloop->addOneTimeRoutine(
                I_MainLoop::RoutineType::System,
                [this]() {
                    connectRedis();
                    is_reconnecting = false;
                },
                "Reconnect Redis for Unified Learning"
            );
        }
    }

    Maybe<std::vector<std::string>>
    discoverActiveQueues()
    {
        std::vector<std::string> queues;

        redisReply *reply =
            static_cast<redisReply *>(redisCommand(redis, "SCAN 0 MATCH unified_learning_entries:* COUNT 128"));

        if (!reply) {
            reconnectRedis();
            return genError("SCAN command returned NULL reply");
        }

        if (reply->type == REDIS_REPLY_ERROR) {
            std::string error_msg = std::string("SCAN command failed: ") + reply->str;
            freeReplyObject(reply);
            reconnectRedis();
            return genError(error_msg);
        }

        if (reply->type == REDIS_REPLY_ARRAY && reply->elements >= 2) {
            redisReply *keys = reply->element[1];
            if (keys && keys->type == REDIS_REPLY_ARRAY) {
                for (size_t i = 0; i < keys->elements; i++) {
                    if (keys->element[i] && keys->element[i]->type == REDIS_REPLY_STRING) {
                        queues.push_back(keys->element[i]->str);
                    }
                }
            }
        } else {
            std::string error_msg = "SCAN returned unexpected reply type: " + std::to_string(reply->type);
            freeReplyObject(reply);
            return genError(error_msg);
        }

        freeReplyObject(reply);
        return queues;
    }

    std::vector<std::string>
    getOrRefreshQueues()
    {
        auto now = i_time_get->getMonotonicTime();
        auto interval = std::chrono::milliseconds(queue_discovery_interval_msec);
        if (cached_queues.empty() || (now - last_discovery) > interval) {
            auto maybe_queues = discoverActiveQueues();
            if (!maybe_queues.ok()) {
                dbgWarning(D_UNIFIED_LEARNING)
                    << "Failed to discover queues: "
                    << maybe_queues.getErr();
                return cached_queues; // Return cached queues on error
            }

            cached_queues = maybe_queues.unpack();
            last_discovery = now;

            dbgTrace(D_UNIFIED_LEARNING)
                << "Discovered "
                << cached_queues.size()
                << " active learning queues";
        }
        return cached_queues;
    }

    void
    processQueue(const std::string &queueKey, int batchSize)
    {
        redisReply *reply = static_cast<redisReply *>(
            redisCommand(redis, "EVALSHA %s 1 %s %d", lua_script_hash.c_str(), queueKey.c_str(), batchSize)
        );

        if (!reply) {

            dbgWarning(D_UNIFIED_LEARNING)
                << "EVALSHA command returned NULL reply for queue: "
                << queueKey;

            reconnectRedis();
            return;
        }

        if (reply->type == REDIS_REPLY_ERROR) {

            dbgWarning(D_UNIFIED_LEARNING)
                << "EVALSHA command failed for queue "
                << queueKey << ": "
                << reply->str;

            freeReplyObject(reply);
            reconnectRedis();
            return;
        }

        if (reply->type != REDIS_REPLY_ARRAY) {

            dbgWarning(D_UNIFIED_LEARNING)
                << "EVALSHA returned unexpected reply type: "
                << reply->type
                << " for queue: "
                << queueKey;

            freeReplyObject(reply);
            return;
        }

        for (size_t i = 0; i < reply->elements; i++) {
            if (reply->element[i] && reply->element[i]->type == REDIS_REPLY_STRING) {
                std::vector<char> data(reply->element[i]->str, reply->element[i]->str + reply->element[i]->len);

                if (!processEntryData(data.data(), data.size())) {
                    dbgTrace(D_UNIFIED_LEARNING)
                        << "Failed to process entry from "
                        << queueKey;
                }
            }
        }

        freeReplyObject(reply);
    }

    void
    stopRedisProcessingRoutine()
    {
        if (processing_routine_id > 0 && mainloop->doesRoutineExist(processing_routine_id)) {
            dbgTrace(D_UNIFIED_LEARNING)
                << "Stopping Redis processing routine with ID: "
                << processing_routine_id;
            mainloop->stop(processing_routine_id);
            processing_routine_id = 0;
        }
    }

    void
    disconnectRedis()
    {
        if (redis) {
            redisFree(redis);
            redis = nullptr;
        }
    }

    void
    saveAndClearAssetSyncUnits()
    {
        dbgTrace(D_UNIFIED_LEARNING)
            << "Saving data for "
            << asset_sync_units.size()
            << " assets";

        for (auto& pair : asset_sync_units) {
            dbgTrace(D_UNIFIED_LEARNING)
                << "Saving data for asset: "
                << pair.first;
            pair.second->saveData();
        }

        asset_sync_units.clear();
    }

    void
    handleNewPolicy()
    {
        bool old_unified_learning_enabled = m_unified_learning_enabled;
        m_unified_learning_enabled = getProfileAgentSettingWithDefault<bool>(
            false,
            "agent.learning.unifiedLearning"
        );
        dbgTrace(D_UNIFIED_LEARNING)
            << "old_unified_learning_enabled is: "
            << old_unified_learning_enabled
            << " new m_unified_learning_enabled is: "
            << m_unified_learning_enabled;

        if (old_unified_learning_enabled != m_unified_learning_enabled) {
            if (m_unified_learning_enabled) {
                dbgInfo(D_UNIFIED_LEARNING) << "Unified Learning enabled via policy, connecting to Redis";
                // Connect to Redis
                if (!connectRedis()) {
                    dbgError(D_UNIFIED_LEARNING) << "Failed to connect to Redis";
                    return;
                }
                // Start continuous Redis processing
                createRedisProcessingRoutine();
            } else {
                dbgInfo(D_UNIFIED_LEARNING) << "Unified Learning disabled via policy, disconnecting from Redis";
                // Stop processing routine
                stopRedisProcessingRoutine();
                // Save and clear all asset sync units before disconnecting
                saveAndClearAssetSyncUnits();
                // Disconnect from Redis
                disconnectRedis();
            }
        }
        int interval_minutes = getProfileAgentSettingWithDefault<int>(
            120,
            "agent.learning.learningSyncInterval"
        );
        std::chrono::minutes new_interval(interval_minutes);

        if (sync_interval != new_interval){
            sync_interval = new_interval;
        }
        // Notify all asset sync units about policy change
        for (auto& pair : asset_sync_units) {
            dbgTrace(D_UNIFIED_LEARNING)
                << "Notifying asset sync unit about policy change: "
                << pair.first;
            pair.second->handleNewPolicy();
        }
    }

    void
    processRedisEntries()
    {
        // Get all active queues
        auto activeQueues = getOrRefreshQueues();
        if (activeQueues.empty()) {
            dbgTrace(D_UNIFIED_LEARNING) << "No active queues found";
            return;
        }

        // Fair batch distribution
        int batchPerQueue = std::max(1, BATCH_SIZE / (int)activeQueues.size());

        dbgTrace(D_UNIFIED_LEARNING) << "Processing " << activeQueues.size()
            << " queues with " << batchPerQueue
            << " entries each";

        for (const auto &queueKey : activeQueues) {
            processQueue(queueKey, batchPerQueue);
        }
    }

    void
    createRedisProcessingRoutine()
    {
        processing_routine_id = mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            std::chrono::milliseconds(10), // 10ms interval to reduce CPU load
            [this]() { processRedisEntries(); },
            "Unified Learning Redis processor",
            true
        );

        dbgInfo(D_UNIFIED_LEARNING) << "Started continuous Redis processing routine (10ms interval)";
    }

    std::shared_ptr<AssetIndicatorsSyncUnit>
    getOrCreateSyncUnit(const std::string& asset_id)
    {
        auto it = asset_sync_units.find(asset_id);
        if (it != asset_sync_units.end()) {
            return it->second;
        }

        auto unit = std::make_shared<AssetIndicatorsSyncUnit>(
            asset_id,
            sync_interval,
            wait_for_sync,
            m_tenant_id+"/"+asset_id+"/CentralizedData"
        );

        asset_sync_units[asset_id] = unit;

        dbgTrace(D_UNIFIED_LEARNING)
            << "Created new sync unit for asset: "
            << asset_id
            << "with sync_interval: "
            << sync_interval
            << " (total assets: "
            << asset_sync_units.size()
            << ")";

        return unit;
    }

    bool
    processEntryData(const char *raw_data, uint16_t data_size)
    {
        std::vector<char> data_buffer(raw_data, raw_data + data_size);

        UnifiedIndicatorsContainer::Entry entry;
        if (!entry.deserialize(data_buffer)) {
            dbgWarning(D_UNIFIED_LEARNING) << "Failed to deserialize entry data";
            return false;
        }

        // Route to appropriate asset sync unit
        if (entry.asset_id.empty()) {
            dbgTrace(D_UNIFIED_LEARNING)
                << "Entry missing asset_id, skipping. Key: "
                << entry.key;
            return false;
        }

        auto sync_unit = getOrCreateSyncUnit(entry.asset_id);
        sync_unit->addEntry(entry);

        return true;
    }

private:
    // Asset management
    std::unordered_map<std::string, std::shared_ptr<AssetIndicatorsSyncUnit>> asset_sync_units;
    std::chrono::minutes sync_interval;
    std::chrono::seconds wait_for_sync;
    std::string m_tenant_id;

    // Redis connections
    redisContext *redis = nullptr;
    std::string lua_script_hash;
    I_MainLoop::RoutineID processing_routine_id = 0;
    bool is_reconnecting = false;

    // Queue discovery and caching
    std::vector<std::string> cached_queues;
    std::chrono::microseconds last_discovery{0};

    // Interfaces
    I_MainLoop *mainloop = nullptr;
    I_TimeGet *i_time_get = nullptr;
    I_AgentDetails *agentDetails = nullptr;
    // Configuration
    std::string redis_host;
    int redis_port;
    int redis_timeout_usec;
    int queue_discovery_interval_msec;
    
    // Policy state
    bool m_unified_learning_enabled;
};

// Component Impl - lightweight shell that delegates to the manager
class UnifiedLearningComponent::Impl : public Singleton::Provide<I_UnifiedLearning>::From<UnifiedLearningComponent>
{
public:
    Impl() = default;

    void
    init()
    {
        // Create the manager here, after all singletons are available
        manager = std::make_unique<UnifiedLearningManager>();
        manager->init();
    }

    void
    fini()
    {
        if (manager) {
            manager->fini();
            manager.reset();
        }
    }

private:
    std::unique_ptr<UnifiedLearningManager> manager;
};

UnifiedLearningComponent::UnifiedLearningComponent() :
    Component("UnifiedLearningComponent"), pimpl(std::make_unique<Impl>())
{}

UnifiedLearningComponent::~UnifiedLearningComponent()
{}

void
UnifiedLearningComponent::preload()
{
    registerExpectedConfiguration<std::string>("connection", "Redis IP");
    registerExpectedConfiguration<int>("connection", "Redis Port");
    registerExpectedConfiguration<int>("connection", "Redis Timeout");
    registerExpectedConfiguration<int>("connection", "Queue Discovery Interval");
}

void
UnifiedLearningComponent::init()
{
    pimpl->init();
}

void
UnifiedLearningComponent::fini()
{
    pimpl->fini();
}
