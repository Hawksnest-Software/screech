//
// debug_logging.h - Debug logging macros for obfuscation library
//

#ifndef DEBUG_LOGGING_H
#define DEBUG_LOGGING_H

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

// Debug logging levels
typedef enum {
    DEBUG_LOG_LEVEL_ERROR = 0,
    DEBUG_LOG_LEVEL_WARNING = 1,
    DEBUG_LOG_LEVEL_INFO = 2,
    DEBUG_LOG_LEVEL_DEBUG = 3,
    DEBUG_LOG_LEVEL_ENDPOINT_SECURITY = 4,
    DEBUG_LOG_LEVEL_FILESYSTEM = 5,
    DEBUG_LOG_LEVEL_PROCESS = 6,
    DEBUG_LOG_LEVEL_IPC = 7
} debug_log_level_t;

// Debug logging functions
void debug_log_init(void);
void debug_log_set_level(debug_log_level_t level);
void debug_log_printf(debug_log_level_t level, const char* fmt, ...);

// Debug logging macros
#ifdef DEBUG
    #define DEBUG_LOG_ERROR(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
    #define DEBUG_LOG_WARNING(fmt, ...) printf("[WARNING] " fmt "\n", ##__VA_ARGS__)
    #define DEBUG_LOG_INFO(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)
    #define DEBUG_LOG_DEBUG(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
    #define DEBUG_LOG_ENDPOINT_SECURITY(fmt, ...) printf("[ENDPOINT] " fmt "\n", ##__VA_ARGS__)
    #define DEBUG_LOG_FILESYSTEM(fmt, ...) printf("[FILESYSTEM] " fmt "\n", ##__VA_ARGS__)
    #define DEBUG_LOG_PROCESS(fmt, ...) printf("[PROCESS] " fmt "\n", ##__VA_ARGS__)
    #define DEBUG_LOG_IPC(fmt, ...) printf("[IPC] " fmt "\n", ##__VA_ARGS__)
#else
    #define DEBUG_LOG_ERROR(fmt, ...) do { } while(0)
    #define DEBUG_LOG_WARNING(fmt, ...) do { } while(0)
    #define DEBUG_LOG_INFO(fmt, ...) do { } while(0)
    #define DEBUG_LOG_DEBUG(fmt, ...) do { } while(0)
    #define DEBUG_LOG_ENDPOINT_SECURITY(fmt, ...) do { } while(0)
    #define DEBUG_LOG_FILESYSTEM(fmt, ...) do { } while(0)
    #define DEBUG_LOG_PROCESS(fmt, ...) do { } while(0)
    #define DEBUG_LOG_IPC(fmt, ...) do { } while(0)
#endif

#ifdef __cplusplus
}
#endif

#endif // DEBUG_LOGGING_H
