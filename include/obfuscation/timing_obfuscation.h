//
// timing_obfuscation.h - Timing-based obfuscation techniques
// Disrupts timing analysis and creates variable execution profiles
//

#ifndef TIMING_OBFUSCATION_H
#define TIMING_OBFUSCATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Timing obfuscation configuration
#define MAX_TIMING_PROFILES 8
#define MAX_DELAY_PATTERNS 16
#define TIMING_NOISE_SAMPLES 32

// Timing profile types
typedef enum {
    TIMING_PROFILE_UNIFORM,      // Constant delays
    TIMING_PROFILE_RANDOM,       // Random delays
    TIMING_PROFILE_GAUSSIAN,     // Gaussian distribution
    TIMING_PROFILE_EXPONENTIAL,  // Exponential distribution
    TIMING_PROFILE_BURST,        // Burst patterns
    TIMING_PROFILE_PERIODIC,     // Periodic patterns
    TIMING_PROFILE_ADAPTIVE,     // Adaptive based on system load
    TIMING_PROFILE_STEGANOGRAPHIC // Hidden in legitimate operations
} timing_profile_t;

// Timing measurement precision
typedef enum {
    TIMING_PRECISION_MICROSECOND,
    TIMING_PRECISION_NANOSECOND,
    TIMING_PRECISION_CPU_CYCLE
} timing_precision_t;

// Timing obfuscation context
typedef struct {
    timing_profile_t profile;
    uint32_t base_delay_us;      // Base delay in microseconds
    uint32_t variance_us;        // Variance in microseconds
    double amplitude;            // Amplitude factor for patterns
    uint32_t period_us;          // Period for periodic patterns
    bool adaptive_enabled;       // Enable adaptive timing
    uint32_t cpu_load_threshold; // CPU load threshold for adaptation
} timing_context_t;

// Timing statistics for analysis resistance
typedef struct {
    uint64_t total_operations;
    uint64_t total_delay_time;
    uint64_t min_delay;
    uint64_t max_delay;
    double mean_delay;
    double variance;
    uint32_t profile_switches;
} timing_stats_t;

// Timing noise generation
typedef struct {
    uint64_t samples[TIMING_NOISE_SAMPLES];
    uint32_t sample_index;
    uint64_t entropy_accumulator;
    bool initialized;
} timing_noise_generator_t;

// Core timing obfuscation functions
void init_timing_obfuscation(void);
void cleanup_timing_obfuscation(void);

// Timing profile management
void set_timing_profile(timing_profile_t profile);
void configure_timing_context(const timing_context_t* context);
timing_context_t* get_current_timing_context(void);
void randomize_timing_profile(void);

// Delay generation functions
void obfuscated_delay(uint32_t base_delay_us);
void obfuscated_delay_with_profile(timing_profile_t profile, uint32_t base_delay_us);
void variable_delay(uint32_t min_us, uint32_t max_us);
void adaptive_delay(const char* operation_name);

// Pattern-based delays
void periodic_delay(uint32_t period_us, double phase);
void burst_delay(uint32_t burst_count, uint32_t burst_interval_us);
void gaussian_delay(uint32_t mean_us, uint32_t stddev_us);
void exponential_delay(double lambda);

// Steganographic timing (hide in legitimate operations)
void steganographic_delay_in_malloc(size_t size);
void steganographic_delay_in_io(const char* operation_type);
void steganographic_delay_in_crypto(const char* algorithm);

// System interaction timing
void cpu_intensive_delay(uint32_t duration_us);
void memory_intensive_delay(uint32_t duration_us);
void io_intensive_delay(uint32_t duration_us);

// Timing measurement and analysis resistance
uint64_t get_precise_timestamp(timing_precision_t precision);
void add_timing_noise(uint64_t* timestamp);
void scramble_timing_measurements(uint64_t* measurements, size_t count);

// Anti-timing-analysis techniques
void insert_fake_timing_checkpoints(void);
void create_timing_decoys(uint32_t count);
void obfuscate_execution_timeline(void);
void generate_false_timing_patterns(void);

// Adaptive timing based on system state
void update_timing_based_on_cpu_load(void);
void update_timing_based_on_memory_pressure(void);
void update_timing_based_on_network_activity(void);

// Timing statistics (for debugging and tuning)
timing_stats_t* get_timing_statistics(void);
void reset_timing_statistics(void);
bool detect_timing_analysis_attempt(void);

// High-level timing obfuscation wrappers
#define TIMING_OBFUSCATED_OPERATION(operation) \
    do { \
        obfuscated_delay(0); \
        operation; \
        adaptive_delay(#operation); \
    } while(0)

#define TIMING_SENSITIVE_OPERATION(operation, min_delay, max_delay) \
    do { \
        variable_delay(min_delay, max_delay); \
        operation; \
        add_timing_noise_to_current_context(); \
    } while(0)

#define STEGANOGRAPHIC_OPERATION(operation, cover_operation) \
    do { \
        steganographic_delay_in_##cover_operation(#operation); \
        operation; \
    } while(0)

// Context-specific timing functions
void add_timing_noise_to_current_context(void);
void switch_timing_profile_randomly(void);
void apply_timing_countermeasures(void);

// Integration with other obfuscation techniques
void combine_timing_with_function_diversification(const char* func_name);
void combine_timing_with_api_misdirection(const char* api_name);

#ifdef __cplusplus
}
#endif

#endif // TIMING_OBFUSCATION_H
