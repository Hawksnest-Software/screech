#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "../Shared/ScreechShared.h"

NS_ASSUME_NONNULL_BEGIN

@interface ScreechFilterDataProvider : NEFilterDataProvider <ScreechMainAppCommunication>

@property (nonatomic, strong) NSXPCConnection *appConnection;
@property (nonatomic, assign) BOOL monitoringEnabled;

// Network monitoring methods
- (void)setupNetworkMonitoring;
- (void)teardownNetworkMonitoring;

// Flow tracking
- (void)trackNewFlow:(NEFilterFlow *)flow;
- (void)updateFlowData:(NEFilterFlow *)flow bytesIn:(uint64_t)bytesIn bytesOut:(uint64_t)bytesOut;

// Process information extraction
- (ScreechNetworkFlow *)createNetworkFlowFromNEFlow:(NEFilterFlow *)flow;
- (NSString *)getProcessNameForPID:(pid_t)pid;
- (NSString *)getProcessPathForPID:(pid_t)pid;

@end

NS_ASSUME_NONNULL_END
