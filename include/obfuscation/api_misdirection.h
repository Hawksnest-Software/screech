//
// api_misdirection.h - API misdirection and decoy function system
// Creates fake API calls and misleading function signatures to confuse analysis
//

#ifndef API_MISDIRECTION_H
#define API_MISDIRECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Configuration
#define MAX_DECOY_FUNCTIONS 32
#define MAX_FAKE_API_CALLS 64
#define MAX_MISDIRECTION_DEPTH 8
#define DECOY_NAME_MAX_LEN 128
#define MAX_MISDIRECTION_TARGETS 16
#define MAX_FAKE_APIS 64

// Decoy function types
typedef enum {
    DECOY_TYPE_NETWORK,
    DECOY_TYPE_FILE_SYSTEM,
    DECOY_TYPE_PROCESS,
    DECOY_TYPE_REGISTRY,
    DECOY_TYPE_MEMORY,
    DECOY_TYPE_CRYPTO,
    DECOY_TYPE_SYSTEM,
    DECOY_TYPE_DEBUG,
    DECOY_TYPE_COUNT
} decoy_type_t;

// Misdirection technique types
typedef enum {
    MISDIRECTION_FAKE_CALLS,
    MISDIRECTION_DUMMY_APIS,
    MISDIRECTION_PROXY_FUNCTIONS,
    MISDIRECTION_LAYERED_INDIRECTION,
    MISDIRECTION_FALSE_POSITIVES,
    MISDIRECTION_COUNT
} misdirection_technique_t;

// Decoy function metadata
typedef struct {
    char name[DECOY_NAME_MAX_LEN];
    decoy_type_t type;
    void (*func_ptr)(void);
    uint32_t call_frequency;
    uint32_t complexity_level;
    bool is_active;
    uint64_t last_called;
} decoy_function_t;

// Fake API call descriptor
typedef struct {
    char api_name[DECOY_NAME_MAX_LEN];
    void* fake_address;
    void* real_address;
    uint32_t call_count;
    bool intercept_enabled;
    uint32_t api_hash;
    uint32_t call_frequency;
} fake_api_call_t;

// Misdirection layer for function indirection
typedef struct {
    void* proxy_func;
    void* real_func;
    uint8_t indirection_depth;
    uint32_t obfuscation_seed;
} misdirection_layer_t;

// Global misdirection registry
typedef struct {
    decoy_function_t decoys[MAX_DECOY_FUNCTIONS];
    fake_api_call_t fake_apis[MAX_FAKE_API_CALLS];
    misdirection_layer_t layers[MAX_MISDIRECTION_DEPTH];
    uint32_t decoy_count;
    uint32_t fake_api_count;
    uint32_t layer_count;
    bool misdirection_active;
    bool selective_mode;
    uint32_t activation_seed;
} misdirection_registry_t;

// API misdirection macros
#define MISDIRECT_CALL(real_func, ...) \
    misdirection_proxy_call((void*)real_func, #real_func, __VA_ARGS__)

#define DECOY_API_CALL(api_name) \
    execute_decoy_api_call(api_name)

#define FAKE_IMPORT(api_name) \
    register_fake_import(#api_name, (void*)fake_##api_name)

// Function pointer obfuscation
#define OBFUSCATED_FUNC_PTR(func) \
    obfuscate_function_pointer((void*)func)

// Core misdirection functions
void init_api_misdirection(void);
void activate_misdirection(bool enable);
void update_misdirection_state(void);
void shutdown_misdirection(void);

// Decoy function management
void register_decoy_function(const char* name, decoy_type_t type, void (*func)(void));
void activate_decoy_functions(decoy_type_t type);
void deactivate_decoy_functions(decoy_type_t type);
void execute_random_decoys(uint32_t count);
void schedule_decoy_execution(uint32_t interval_ms);

// Fake API management
void register_fake_api(const char* api_name, void* fake_func, void* real_func);
void* get_fake_api_address(const char* api_name);
bool intercept_api_call(const char* api_name, void** real_func);
void execute_decoy_api_call(const char* api_name);

// Function indirection and proxy calls
void* create_misdirection_layer(void* real_func, uint8_t depth);
void* misdirection_proxy_call(void* real_func, const char* func_name, ...);
void* obfuscate_function_pointer(void* func_ptr);
void rotate_misdirection_layers(void);

// Specific decoy function categories

// Network decoys
void decoy_socket_init(void);
void decoy_http_request(void);
void decoy_dns_lookup(void);
void decoy_tcp_connect(void);
void decoy_ssl_handshake(void);

// File system decoys
void decoy_file_open(void);
void decoy_directory_scan(void);
void decoy_file_hash(void);
void decoy_registry_read(void);
void decoy_config_parse(void);

// Process decoys
void decoy_process_enum(void);
void decoy_thread_create(void);
void decoy_memory_alloc(void);
void decoy_dll_load(void);
void decoy_service_query(void);

// Crypto decoys
void decoy_hash_compute(void);
void decoy_encrypt_data(void);
void decoy_key_generation(void);
void decoy_random_bytes(void);
void decoy_certificate_check(void);

// System decoys
void decoy_system_info(void);
void decoy_hardware_query(void);
void decoy_environment_check(void);
void decoy_privilege_check(void);
void decoy_antivirus_scan(void);

// Debug/analysis decoys (false positives for analysts)
void decoy_debugger_check(void);
void decoy_vm_detection(void);
void decoy_sandbox_evasion(void);
void decoy_integrity_check(void);
void decoy_license_validation(void);

// Advanced misdirection techniques
void create_fake_import_table(void);
void generate_false_call_graph(void);
void insert_misleading_strings(void);
void create_dummy_exception_handlers(void);
void generate_fake_debug_symbols(void);

// Timing-based misdirection
void random_delay_execution(void);
void schedule_background_decoys(void);
void create_timing_noise(void);

// Analysis confusion techniques
void generate_red_herring_functions(void);
void create_misleading_data_structures(void);
void insert_fake_vulnerabilities(void);
void generate_false_crypto_operations(void);

// Runtime configuration
void set_misdirection_aggressiveness(uint8_t level);
void configure_decoy_frequency(decoy_type_t type, uint32_t frequency);
void enable_selective_misdirection(const char* target_functions[], uint32_t count);
void update_misdirection_seeds(void);

// Statistics and monitoring
uint32_t get_decoy_call_count(decoy_type_t type);
uint32_t get_misdirection_overhead(void);
bool is_misdirection_detected(void);
void reset_misdirection_stats(void);

#ifdef __cplusplus
}
#endif

#endif // API_MISDIRECTION_H
