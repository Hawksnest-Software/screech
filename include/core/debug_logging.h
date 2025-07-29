//
// debug_logging.h - Debug logging system
// Only shows debug messages in debug builds, silent in release
//

#ifndef DEBUG_LOGGING_H
#define DEBUG_LOGGING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Logging levels
typedef enum {
    DEBUG_LOG_SILENT = 0,
    DEBUG_LOG_ERROR = 1,
    DEBUG_LOG_WARNING = 2,
    DEBUG_LOG_INFO = 3,
    DEBUG_LOG_DEBUG = 4
} DebugLogLevel;

// Initialize logging system
void debug_log_init(void);
void debug_log_set_level(DebugLogLevel level);
bool debug_log_should_log(DebugLogLevel level);

// Core logging functions
void debug_log_message(DebugLogLevel level, const char* format, ...);
void debug_log_binary_data(const char* label, const void* data, size_t len);

// Convenience macros that compile to nothing in release builds
// Check for multiple debug defines used by different build systems
#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
    #define DEBUG_LOG_ERROR(fmt, ...) debug_log_message(DEBUG_LOG_ERROR, fmt, ##__VA_ARGS__)
    #define DEBUG_LOG_WARNING(fmt, ...) debug_log_message(DEBUG_LOG_WARNING, fmt, ##__VA_ARGS__)
    #define DEBUG_LOG_INFO(fmt, ...) debug_log_message(DEBUG_LOG_INFO, fmt, ##__VA_ARGS__)
    #define DEBUG_LOG_DEBUG(fmt, ...) debug_log_message(DEBUG_LOG_DEBUG, fmt, ##__VA_ARGS__)
    #define DEBUG_LOG_BINARY(label, data, len) debug_log_binary_data(label, data, len)
    
    // Legacy compatibility - keep old STEALTH_LOG macros for existing code
    #define STEALTH_LOG_ERROR(fmt, ...) debug_log_message(DEBUG_LOG_ERROR, fmt, ##__VA_ARGS__)
    #define STEALTH_LOG_WARNING(fmt, ...) debug_log_message(DEBUG_LOG_WARNING, fmt, ##__VA_ARGS__)
    #define STEALTH_LOG_INFO(fmt, ...) debug_log_message(DEBUG_LOG_INFO, fmt, ##__VA_ARGS__)
    #define STEALTH_LOG_DEBUG(fmt, ...) debug_log_message(DEBUG_LOG_DEBUG, fmt, ##__VA_ARGS__)
    #define STEALTH_LOG_BINARY(label, data, len) debug_log_binary_data(label, data, len)
#else
    // Complete no-ops in release builds - compiler will optimize these away
    #define DEBUG_LOG_ERROR(fmt, ...) ((void)0)
    #define DEBUG_LOG_WARNING(fmt, ...) ((void)0) 
    #define DEBUG_LOG_INFO(fmt, ...) ((void)0)
    #define DEBUG_LOG_DEBUG(fmt, ...) ((void)0)
    #define DEBUG_LOG_BINARY(label, data, len) ((void)0)
    
    // Legacy compatibility
    #define STEALTH_LOG_ERROR(fmt, ...) ((void)0)
    #define STEALTH_LOG_WARNING(fmt, ...) ((void)0) 
    #define STEALTH_LOG_INFO(fmt, ...) ((void)0)
    #define STEALTH_LOG_DEBUG(fmt, ...) ((void)0)
    #define STEALTH_LOG_BINARY(label, data, len) ((void)0)
#endif

// Legacy printf replacement for existing code
#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
    #define DEBUG_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
    #define STEALTH_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)  // Legacy compatibility
#else
    #define DEBUG_PRINTF(fmt, ...) ((void)0)
    #define STEALTH_PRINTF(fmt, ...) ((void)0)
#endif

// Conditional execution - only runs in debug builds
#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
    #define DEBUG_ONLY(code) do { code } while(0)
#else
    #define DEBUG_ONLY(code) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif // DEBUG_LOGGING_H
