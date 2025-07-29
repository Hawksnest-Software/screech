#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import "../Shared/ScreechShared.h"

NS_ASSUME_NONNULL_BEGIN

@interface ScreechMainApp : NSObject <ScreechExtensionCommunication>

// Network Extension Management
@property (nonatomic, strong) NEFilterManager *filterManager;
@property (nonatomic, strong) NSXPCConnection *extensionConnection;
@property (nonatomic, assign) BOOL networkExtensionActive;

// Endpoint Security
@property (nonatomic, assign) es_client_t *esClient;
@property (nonatomic, assign) BOOL endpointSecurityActive;

// Configuration
@property (nonatomic, strong) NSMutableDictionary *configuration;
@property (nonatomic, assign) BOOL shouldStop;

// Main control methods
- (BOOL)startMonitoring;
- (void)stopMonitoring;
- (void)runMainLoop;

// Network Extension management
- (void)setupNetworkExtension;
- (void)startNetworkExtension;
- (void)stopNetworkExtension;

// Endpoint Security management
- (BOOL)setupEndpointSecurity;
- (void)teardownEndpointSecurity;

// Event processing
- (void)processNetworkFlow:(ScreechNetworkFlow *)flow;
- (void)processEndpointSecurityEvent:(const es_message_t *)message;

// Logging and output (matching Linux eBPF format)
- (void)logNetworkEvent:(ScreechNetworkFlow *)flow;
- (void)logProcessEvent:(ScreechProcessEvent *)event;
- (void)logFileEvent:(ScreechFileEvent *)event;
- (void)writeToLogFile:(NSString *)filename content:(NSString *)content;

// File event processing
- (void)processFileEvent:(ScreechFileEvent *)event;

@end

NS_ASSUME_NONNULL_END
