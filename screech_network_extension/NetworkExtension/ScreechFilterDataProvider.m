#import "ScreechFilterDataProvider.h"
#import <libproc.h>
#import <sys/proc_info.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <bsm/libbsm.h>

@interface ScreechFilterDataProvider ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, ScreechNetworkFlow *> *activeFlows;
@property (nonatomic, strong) dispatch_queue_t processingQueue;
@end

@implementation ScreechFilterDataProvider

#pragma mark - NEFilterDataProvider Overrides

- (instancetype)init {
    self = [super init];
    if (self) {
        self.activeFlows = [[NSMutableDictionary alloc] init];
        self.processingQueue = dispatch_queue_create("com.screech.networkextension.processing", DISPATCH_QUEUE_SERIAL);
        self.monitoringEnabled = YES;
        [ScreechLogger logInfo:@"ScreechFilterDataProvider initialized"];
    }
    return self;
}

- (void)startFilterWithCompletionHandler:(void (^)(NSError * _Nullable error))completionHandler {
    [ScreechLogger logInfo:@"Starting Screech Network Extension"];
    
    [self setupNetworkMonitoring];
    [self establishAppConnection];
    
    // Notify completion
    completionHandler(nil);
    
    // Notify main app that extension started
    if (self.appConnection) {
        id<ScreechExtensionCommunication> remoteProxy = [self.appConnection remoteObjectProxy];
        [remoteProxy extensionStarted];
    }
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    [ScreechLogger logInfo:[NSString stringWithFormat:@"Stopping Screech Network Extension with reason: %ld", (long)reason]];
    
    [self teardownNetworkMonitoring];
    
    // Notify main app that extension stopped
    if (self.appConnection) {
        id<ScreechExtensionCommunication> remoteProxy = [self.appConnection remoteObjectProxy];
        [remoteProxy extensionStopped];
    }
    
    [self.appConnection invalidate];
    self.appConnection = nil;
    
    completionHandler();
}

- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if (!self.monitoringEnabled) {
        return [NEFilterNewFlowVerdict allowVerdict];
    }
    
    [ScreechLogger logDebug:[NSString stringWithFormat:@"New flow detected: %@", flow.description]];
    
    // Track this flow
    [self trackNewFlow:flow];
    
    // Allow all traffic (we're monitoring, not filtering)
    return [NEFilterNewFlowVerdict allowVerdict];
}

- (NEFilterDataVerdict *)handleInboundDataFromFlow:(NEFilterFlow *)flow readBytesStartOffset:(NSUInteger)offset readBytes:(NSData *)readBytes {
    if (!self.monitoringEnabled) {
        return [NEFilterDataVerdict allowVerdict];
    }
    
    // Update flow statistics
    [self updateFlowData:flow bytesIn:readBytes.length bytesOut:0];
    
    return [NEFilterDataVerdict allowVerdict];
}

- (NEFilterDataVerdict *)handleOutboundDataFromFlow:(NEFilterFlow *)flow readBytesStartOffset:(NSUInteger)offset readBytes:(NSData *)readBytes {
    if (!self.monitoringEnabled) {
        return [NEFilterDataVerdict allowVerdict];
    }
    
    // Update flow statistics
    [self updateFlowData:flow bytesIn:0 bytesOut:readBytes.length];
    
    return [NEFilterDataVerdict allowVerdict];
}

- (void)handleFlowClosed:(NEFilterFlow *)flow {
    [ScreechLogger logDebug:[NSString stringWithFormat:@"Flow closed: %@", flow.description]];
    
    NSString *flowKey = [self flowKeyForFlow:flow];
    dispatch_async(self.processingQueue, ^{
        [self.activeFlows removeObjectForKey:flowKey];
    });
}

#pragma mark - Network Monitoring Setup

- (void)setupNetworkMonitoring {
    [ScreechLogger logInfo:@"Setting up network monitoring"];
    // Additional setup if needed
}

- (void)teardownNetworkMonitoring {
    [ScreechLogger logInfo:@"Tearing down network monitoring"];
    
    dispatch_async(self.processingQueue, ^{
        [self.activeFlows removeAllObjects];
    });
}

#pragma mark - Flow Tracking

- (void)trackNewFlow:(NEFilterFlow *)flow {
    ScreechNetworkFlow *networkFlow = [self createNetworkFlowFromNEFlow:flow];
    if (!networkFlow) {
        return;
    }
    
    NSString *flowKey = [self flowKeyForFlow:flow];
    
    dispatch_async(self.processingQueue, ^{
        // Store the flow for tracking
        self.activeFlows[flowKey] = networkFlow;
        
        // Notify main app about new connection
        if (self.appConnection) {
            id<ScreechExtensionCommunication> remoteProxy = [self.appConnection remoteObjectProxy];
            [remoteProxy networkFlowDetected:networkFlow];
        }
        
        [ScreechLogger logInfo:[NSString stringWithFormat:@"New network flow: %@", networkFlow.description]];
    });
}

- (void)updateFlowData:(NEFilterFlow *)flow bytesIn:(uint64_t)bytesIn bytesOut:(uint64_t)bytesOut {
    NSString *flowKey = [self flowKeyForFlow:flow];
    
    dispatch_async(self.processingQueue, ^{
        ScreechNetworkFlow *networkFlow = self.activeFlows[flowKey];
        if (networkFlow) {
            networkFlow.bytesIn += bytesIn;
            networkFlow.bytesOut += bytesOut;
        }
    });
}

- (NSString *)flowKeyForFlow:(NEFilterFlow *)flow {
    if ([flow isKindOfClass:[NEFilterSocketFlow class]]) {
        NEFilterSocketFlow *socketFlow = (NEFilterSocketFlow *)flow;
        // Network Extension endpoints don't have direct hostname/port properties
        // Use flow description as fallback
        return [NSString stringWithFormat:@"Flow_%p", (void*)socketFlow];
    }
    return flow.description;
}

#pragma mark - Process Information

- (ScreechNetworkFlow *)createNetworkFlowFromNEFlow:(NEFilterFlow *)flow {
    ScreechNetworkFlow *networkFlow = [[ScreechNetworkFlow alloc] init];
    
    // Use basic flow information available
    networkFlow.sourceIP = @"unknown";
    networkFlow.destinationIP = @"unknown";
    networkFlow.sourcePort = 0;
    networkFlow.destinationPort = 0;
    networkFlow.protocol = IPPROTO_TCP; // Default to TCP
    
    // Extract what we can from the flow description
    NSString *flowDesc = flow.description;
    if (flowDesc) {
        // Try to extract some basic info from description
        if ([flowDesc containsString:@"TCP"]) {
            networkFlow.protocol = IPPROTO_TCP;
        } else if ([flowDesc containsString:@"UDP"]) {
            networkFlow.protocol = IPPROTO_UDP;
        }
    }
    
    // Get process information from audit token if available
    pid_t pid = 0;
    if (flow.sourceAppAuditToken) {
        // Extract PID from audit token data
        const audit_token_t *token = (const audit_token_t *)[flow.sourceAppAuditToken bytes];
        if (token && [flow.sourceAppAuditToken length] >= sizeof(audit_token_t)) {
            pid = audit_token_to_pid(*token);
        }
    }
    
    networkFlow.processID = pid;
    networkFlow.processName = [self getProcessNameForPID:pid];
    networkFlow.processPath = [self getProcessPathForPID:pid];
    
    // Get user/group information
    if (pid > 0) {
        struct proc_bsdinfo procInfo;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) > 0) {
            networkFlow.userID = procInfo.pbi_uid;
            networkFlow.groupID = procInfo.pbi_gid;
        }
    }
    
    networkFlow.timestamp = [NSDate date];
    networkFlow.eventType = ScreechEventTypeNetworkFlow;
    networkFlow.bytesIn = 0;
    networkFlow.bytesOut = 0;
    networkFlow.direction = @"outbound";
    
    return networkFlow;
}

- (NSString *)getProcessNameForPID:(pid_t)pid {
    struct proc_bsdinfo procInfo;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) > 0) {
        return [NSString stringWithUTF8String:procInfo.pbi_comm];
    }
    return [NSString stringWithFormat:@"pid_%d", pid];
}

- (NSString *)getProcessPathForPID:(pid_t)pid {
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
        return [NSString stringWithUTF8String:pathbuf];
    }
    return @"unknown";
}

#pragma mark - XPC Communication

- (void)establishAppConnection {
    self.appConnection = [[NSXPCConnection alloc] initWithMachServiceName:ScreechNetworkExtensionMachServiceName options:0];
    
    self.appConnection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ScreechExtensionCommunication)];
    self.appConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ScreechMainAppCommunication)];
    self.appConnection.exportedObject = self;
    
    ScreechFilterDataProvider *dataProvider = self;  // Avoid retain cycle
    self.appConnection.invalidationHandler = ^{
        [ScreechLogger logError:@"XPC connection invalidated"];
        dataProvider.appConnection = nil;
    };
    
    self.appConnection.interruptionHandler = ^{
        [ScreechLogger logError:@"XPC connection interrupted"];
    };
    
    [self.appConnection resume];
    [ScreechLogger logInfo:@"XPC connection established"];
}

#pragma mark - ScreechMainAppCommunication Protocol

- (void)processEventDetected:(ScreechProcessEvent *)event {
    // Received process event from main app - could correlate with network flows
    [ScreechLogger logDebug:[NSString stringWithFormat:@"Received process event: %@", event.description]];
}

- (void)configurationChanged:(NSDictionary *)config {
    // Handle configuration changes from main app
    NSNumber *enabled = config[@"monitoringEnabled"];
    if (enabled) {
        self.monitoringEnabled = [enabled boolValue];
        [ScreechLogger logInfo:[NSString stringWithFormat:@"Monitoring enabled changed to: %@", enabled]];
    }
}

- (void)startMonitoring {
    self.monitoringEnabled = YES;
    [ScreechLogger logInfo:@"Network monitoring started by main app"];
}

- (void)stopMonitoring {
    self.monitoringEnabled = NO;
    [ScreechLogger logInfo:@"Network monitoring stopped by main app"];
}

@end
