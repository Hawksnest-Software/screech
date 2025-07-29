#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "../Shared/SystemFramework.h"

NS_ASSUME_NONNULL_BEGIN

@interface CoreNetworkProvider : NEFilterDataProvider <SystemServiceInterface>

@property (nonatomic, strong) NSXPCConnection *serviceConnection;
@property (nonatomic, assign) BOOL analyticsEnabled;

// Network analytics methods
- (void)initializeNetworkAnalytics;
- (void)terminateNetworkAnalytics;

// Flow activity tracking
- (void)recordNetworkFlow:(NEFilterFlow *)flow;
- (void)updateFlowMetrics:(NEFilterFlow *)flow inboundData:(uint64_t)inboundData outboundData:(uint64_t)outboundData;

// Process information extraction with obfuscated method names
- (SystemNetworkFlow *)extractNetworkActivityFromNEFlow:(NEFilterFlow *)flow;
- (NSString *)getProcessLabelForPID:(pid_t)pid;
- (NSString *)getProcessLocationForPID:(pid_t)pid;

@end

NS_ASSUME_NONNULL_END
