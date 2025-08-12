//
// debug_logging.c - Debug logging implementation
//

#include "debug_logging.h"

static debug_log_level_t current_level = DEBUG_LOG_LEVEL_INFO;

void debug_log_init(void) {
    // Simple initialization - nothing needed for printf-based logging
}

void debug_log_set_level(debug_log_level_t level) {
    current_level = level;
}

void debug_log_printf(debug_log_level_t level, const char* fmt, ...) {
    if (level <= current_level) {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
}
