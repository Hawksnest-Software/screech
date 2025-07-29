//
// stealth_logging.h - Stealth logging system
// Redirects to debug_logging for consolidated logging
//

#ifndef STEALTH_LOGGING_H
#define STEALTH_LOGGING_H

#include "debug_logging.h"

#ifdef __cplusplus
extern "C" {
#endif

// Redirect stealth logging to debug logging
#define stealth_log_init() debug_log_init()
#define stealth_log_message(level, fmt, ...) debug_log_message((DebugLogLevel)(level), fmt, ##__VA_ARGS__)
#define stealth_log_binary_data(label, data, len) debug_log_binary_data(label, data, len)

// Map stealth log levels to debug log levels
#define STEALTH_LOG_SILENT  DEBUG_LOG_SILENT
#define STEALTH_LOG_ERROR   DEBUG_LOG_ERROR
#define STEALTH_LOG_WARNING DEBUG_LOG_WARNING
#define STEALTH_LOG_INFO    DEBUG_LOG_INFO
#define STEALTH_LOG_DEBUG   DEBUG_LOG_DEBUG

// Convenience macros that compile to nothing in release builds
// Check for multiple debug defines used by different build systems
#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
    #define STEALTH_LOG_ERROR(fmt, ...) stealth_log_message(STEALTH_LOG_ERROR, fmt, ##__VA_ARGS__)
    #define STEALTH_LOG_WARNING(fmt, ...) stealth_log_message(STEALTH_LOG_WARNING, fmt, ##__VA_ARGS__)
    #define STEALTH_LOG_INFO(fmt, ...) stealth_log_message(STEALTH_LOG_INFO, fmt, ##__VA_ARGS__)
    #define STEALTH_LOG_DEBUG(fmt, ...) stealth_log_message(STEALTH_LOG_DEBUG, fmt, ##__VA_ARGS__)
    #define STEALTH_LOG_BINARY(label, data, len) stealth_log_binary_data(label, data, len)
#else
    // Complete no-ops in release builds - compiler will optimize these away
    #define STEALTH_LOG_ERROR(fmt, ...) ((void)0)
    #define STEALTH_LOG_WARNING(fmt, ...) ((void)0) 
    #define STEALTH_LOG_INFO(fmt, ...) ((void)0)
    #define STEALTH_LOG_DEBUG(fmt, ...) ((void)0)
    #define STEALTH_LOG_BINARY(label, data, len) ((void)0)
#endif

// Legacy printf replacement for existing code
#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
    #define STEALTH_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
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

#endif // STEALTH_LOGGING_H
