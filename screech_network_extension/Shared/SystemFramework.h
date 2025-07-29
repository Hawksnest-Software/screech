#ifndef SystemFramework_h
#define SystemFramework_h

#import <Foundation/Foundation.h>
#import <Network/Network.h>

#ifdef __cplusplus
extern "C" {
#endif

// System event types for analytics monitoring
typedef NS_ENUM(NSInteger, SysAnalyticsEventType) {
    SysAnalyticsEventTypeNetworkActivity = 0,
    SysAnalyticsEventTypeProcessActivity = 1,
    SysAnalyticsEventTypeProcessSpawn = 2,
    SysAnalyticsEventTypeProcessTerminate = 3,
    SysAnalyticsEventTypeConnectionEstablish = 4,
    SysAnalyticsEventTypeSocketBind = 5,
    SysAnalyticsEventTypeFileOperation = 6,
    SysAnalyticsEventTypeFileModification = 7,
    SysAnalyticsEventTypeFileAccess = 8
};

// Network flow data structure for system analytics
@interface SystemNetworkFlow : NSObject <NSSecureCoding>
@property (nonatomic, strong) NSString *srcAddr;
@property (nonatomic, strong) NSString *dstAddr;
@property (nonatomic, assign) uint16_t srcEndpoint;
@property (nonatomic, assign) uint16_t dstEndpoint;
@property (nonatomic, assign) uint8_t transportProtocol; // IPPROTO_TCP, IPPROTO_UDP
@property (nonatomic, assign) pid_t processIdentifier;
@property (nonatomic, strong) NSString *processLabel;
@property (nonatomic, strong) NSString *processLocation;
@property (nonatomic, assign) uid_t userIdentifier;
@property (nonatomic, assign) gid_t groupIdentifier;
@property (nonatomic, strong) NSDate *eventTimestamp;
@property (nonatomic, assign) SysAnalyticsEventType analyticsType;
@property (nonatomic, assign) uint64_t inboundBytes;
@property (nonatomic, assign) uint64_t outboundBytes;
@property (nonatomic, strong) NSString *flowDirection; // "in" or "out"
@end

// Process activity data structure for system monitoring
@interface SystemProcessActivity : NSObject <NSSecureCoding>
@property (nonatomic, assign) pid_t processIdentifier;
@property (nonatomic, assign) pid_t parentProcessIdentifier;
@property (nonatomic, strong) NSString *processLabel;
@property (nonatomic, strong) NSString *processLocation;
@property (nonatomic, assign) uid_t userIdentifier;
@property (nonatomic, assign) gid_t groupIdentifier;
@property (nonatomic, strong) NSDate *eventTimestamp;
@property (nonatomic, assign) SysAnalyticsEventType analyticsType;
@property (nonatomic, strong) NSArray<NSString *> *launchParameters; // For spawn events
@property (nonatomic, assign) int terminationCode; // For termination events
@end

// File system activity data structure for monitoring
@interface SystemFileActivity : NSObject <NSSecureCoding>
@property (nonatomic, assign) pid_t processIdentifier;
@property (nonatomic, assign) pid_t parentProcessIdentifier;
@property (nonatomic, strong) NSString *processLabel;
@property (nonatomic, strong) NSString *processLocation;
@property (nonatomic, assign) uid_t userIdentifier;
@property (nonatomic, assign) gid_t groupIdentifier;
@property (nonatomic, strong) NSDate *eventTimestamp;
@property (nonatomic, assign) SysAnalyticsEventType analyticsType;
@property (nonatomic, strong) NSString *targetPath; // Target file path
@property (nonatomic, strong) NSString *targetName; // Target file name
@property (nonatomic, assign) uint64_t dataSize; // File size for write/create events
@property (nonatomic, assign) mode_t accessMode; // File permissions
@property (nonatomic, strong) NSString *operationType; // "CREATE", "WRITE", "READ"
@end

// Communication interface between system service and analytics provider
@protocol SystemProviderInterface <NSObject>
- (void)networkActivityDetected:(SystemNetworkFlow *)activity;
- (void)providerServiceStarted;
- (void)providerServiceStopped;
- (void)providerServiceError:(NSError *)error;
@end

@protocol SystemServiceInterface <NSObject>
- (void)processActivityDetected:(SystemProcessActivity *)activity;
- (void)configurationUpdated:(NSDictionary *)configuration;
- (void)enableMonitoring;
- (void)disableMonitoring;
@end

// System service identifiers (obfuscated)
extern NSString * const SystemProviderMachServiceName;
extern NSString * const SystemAnalyticsServiceBundleID;

// System logging utilities with obfuscated names
@interface SystemLoggingService : NSObject
+ (void)logInformation:(NSString *)message;
+ (void)logFailure:(NSString *)message;
+ (void)logDiagnostics:(NSString *)message;
+ (void)appendToAnalyticsFile:(NSString *)filename content:(NSString *)content;
@end

#ifdef __cplusplus
}
#endif

#endif /* SystemFramework_h */
