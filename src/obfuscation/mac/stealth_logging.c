//
// stealth_logging.c - Stealth logging implementation
//

#include "stealth_logging.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>

static StealthLogLevel current_log_level = STEALTH_LOG_WARNING;
static bool logging_initialized = false;

void stealth_log_init(void) {
    if (logging_initialized) return;
    
#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
    current_log_level = STEALTH_LOG_DEBUG;
#else
    current_log_level = STEALTH_LOG_SILENT;
#endif
    
    logging_initialized = true;
}

void stealth_log_set_level(StealthLogLevel level) {
    current_log_level = level;
}

bool stealth_log_should_log(StealthLogLevel level) {
#if !defined(DEBUG) && !defined(_DEBUG) && defined(NDEBUG)
    // In release builds, never log anything
    return false;
#else
    return logging_initialized && (level <= current_log_level);
#endif
}

void stealth_log_message(StealthLogLevel level, const char* format, ...) {
#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
    if (!stealth_log_should_log(level)) return;
    
    // Get current time for timestamp
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm* tm_info = localtime(&tv.tv_sec);
    
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
    snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp), 
             ".%03d", (int)(tv.tv_usec / 1000));
    
    // Determine log level prefix
    const char* level_str = "";
    switch (level) {
        case STEALTH_LOG_ERROR:   level_str = "[ERROR]"; break;
        case STEALTH_LOG_WARNING: level_str = "[WARN]";  break;
        case STEALTH_LOG_INFO:    level_str = "[INFO]";  break;
        case STEALTH_LOG_DEBUG:   level_str = "[DEBUG]"; break;
        default:                  level_str = "[LOG]";   break;
    }
    
    // Print timestamp and level
    printf("%s %s ", timestamp, level_str);
    
    // Print the actual message
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\n");
    fflush(stdout);
#else
    // Suppress unused parameter warnings in release builds
    (void)level;
    (void)format;
#endif
}

void stealth_log_binary_data(const char* label, const void* data, size_t len) {
#if defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)
    if (!stealth_log_should_log(STEALTH_LOG_DEBUG)) return;
    
    const uint8_t* bytes = (const uint8_t*)data;
    printf("[DEBUG] %s (%zu bytes):\n", label, len);
    
    for (size_t i = 0; i < len; i += 16) {
        printf("  %04zx: ", i);
        
        // Print hex bytes
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            printf("%02x ", bytes[i + j]);
        }
        
        // Pad with spaces if less than 16 bytes
        for (size_t j = len - i; j < 16; j++) {
            printf("   ");
        }
        
        printf(" ");
        
        // Print ASCII representation
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            uint8_t c = bytes[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        
        printf("\n");
    }
    
    fflush(stdout);
#else
    // Suppress unused parameter warnings
    (void)label;
    (void)data;
    (void)len;  
#endif
}
