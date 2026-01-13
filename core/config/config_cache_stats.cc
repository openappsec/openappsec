#include <atomic>

// Forward declaration of CacheStats struct
struct CacheStats {
    static std::atomic<uint64_t> hits;
    static std::atomic<uint64_t> misses;
    static bool tracking_enabled;
};

// Define static members for cache statistics
std::atomic<uint64_t> CacheStats::hits{0};
std::atomic<uint64_t> CacheStats::misses{0};
bool CacheStats::tracking_enabled = false;
