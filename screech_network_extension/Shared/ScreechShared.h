#ifndef ScreechShared_h
#define ScreechShared_h

#import <Foundation/Foundation.h>
#import <Network/Network.h>

#ifdef __cplusplus
extern "C" {
#endif

// Event types matching Linux eBPF functionality
typedef NS_ENUM(NSInteger, ScreechEventType) {
    ScreechEventTypeNetworkFlow = 0,
    ScreechEventTypeProcessExec = 1,
    ScreechEventTypeProcessFork = 2,
    ScreechEventTypeProcessExit = 3,
    ScreechEventTypeNetworkConnection = 4,
    ScreechEventTypeNetworkBind = 5,
    ScreechEventTypeFileCreate = 6,
    ScreechEventTypeFileWrite = 7,
    ScreechEventTypeFileRead = 8
};

// Network flow information (equivalent to Linux eBPF connection_event)
@interface ScreechNetworkFlow : NSObject <NSSecureCoding>
@property (nonatomic, strong) NSString *sourceIP;
@property (nonatomic, strong) NSString *destinationIP;
@property (nonatomic, assign) uint16_t sourcePort;
@property (nonatomic, assign) uint16_t destinationPort;
@property (nonatomic, assign) uint8_t protocol; // IPPROTO_TCP, IPPROTO_UDP
@property (nonatomic, assign) pid_t processID;
@property (nonatomic, strong) NSString *processName;
@property (nonatomic, strong) NSString *processPath;
@property (nonatomic, assign) uid_t userID;
@property (nonatomic, assign) gid_t groupID;
@property (nonatomic, strong) NSDate *timestamp;
@property (nonatomic, assign) ScreechEventType eventType;
@property (nonatomic, assign) uint64_t bytesIn;
@property (nonatomic, assign) uint64_t bytesOut;
@property (nonatomic, strong) NSString *direction; // "inbound" or "outbound"
@end

// Process information (from Endpoint Security)
@interface ScreechProcessEvent : NSObject <NSSecureCoding>
@property (nonatomic, assign) pid_t processID;
@property (nonatomic, assign) pid_t parentProcessID;
@property (nonatomic, strong) NSString *processName;
@property (nonatomic, strong) NSString *processPath;
@property (nonatomic, assign) uid_t userID;
@property (nonatomic, assign) gid_t groupID;
@property (nonatomic, strong) NSDate *timestamp;
@property (nonatomic, assign) ScreechEventType eventType;
@property (nonatomic, strong) NSArray<NSString *> *arguments; // For exec events
@property (nonatomic, assign) int exitCode; // For exit events
@end

// File event information (from Endpoint Security)
@interface ScreechFileEvent : NSObject <NSSecureCoding>
@property (nonatomic, assign) pid_t processID;
@property (nonatomic, assign) pid_t parentProcessID;
@property (nonatomic, strong) NSString *processName;
@property (nonatomic, strong) NSString *processPath;
@property (nonatomic, assign) uid_t userID;
@property (nonatomic, assign) gid_t groupID;
@property (nonatomic, strong) NSDate *timestamp;
@property (nonatomic, assign) ScreechEventType eventType;
@property (nonatomic, strong) NSString *filePath; // Target file path
@property (nonatomic, strong) NSString *fileName; // Target file name
@property (nonatomic, assign) uint64_t fileSize; // File size for write/create events
@property (nonatomic, assign) mode_t fileMode; // File permissions
@property (nonatomic, strong) NSString *fileOperation; // "CREATE", "WRITE", "READ"
@end

// Communication protocol between main app and network extension
@protocol ScreechExtensionCommunication <NSObject>
- (void)networkFlowDetected:(ScreechNetworkFlow *)flow;
- (void)extensionStarted;
- (void)extensionStopped;
- (void)extensionError:(NSError *)error;
@end

@protocol ScreechMainAppCommunication <NSObject>
- (void)processEventDetected:(ScreechProcessEvent *)event;
- (void)configurationChanged:(NSDictionary *)config;
- (void)startMonitoring;
- (void)stopMonitoring;
@end

// XPC service identifiers
extern NSString * const ScreechNetworkExtensionMachServiceName;
extern NSString * const ScreechMainAppBundleID;

// Logging utilities
@interface ScreechLogger : NSObject
+ (void)logInfo:(NSString *)message;
+ (void)logError:(NSString *)message;
+ (void)logDebug:(NSString *)message;
+ (void)writeToFile:(NSString *)filename content:(NSString *)content;
@end

#ifdef __cplusplus
}
#endif

#endif /* ScreechShared_h */
