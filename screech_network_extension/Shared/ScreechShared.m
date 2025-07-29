#import "ScreechShared.h"
#import <os/log.h>
#import <netinet/in.h>

// XPC service identifiers
NSString * const ScreechNetworkExtensionMachServiceName = @"com.screech.networkextension";
NSString * const ScreechMainAppBundleID = @"com.screech.mainapp";

@implementation ScreechNetworkFlow

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.sourceIP forKey:@"sourceIP"];
    [coder encodeObject:self.destinationIP forKey:@"destinationIP"];
    [coder encodeInt:self.sourcePort forKey:@"sourcePort"];
    [coder encodeInt:self.destinationPort forKey:@"destinationPort"];
    [coder encodeInt:self.protocol forKey:@"protocol"];
    [coder encodeInt:self.processID forKey:@"processID"];
    [coder encodeObject:self.processName forKey:@"processName"];
    [coder encodeObject:self.processPath forKey:@"processPath"];
    [coder encodeInt:self.userID forKey:@"userID"];
    [coder encodeInt:self.groupID forKey:@"groupID"];
    [coder encodeObject:self.timestamp forKey:@"timestamp"];
    [coder encodeInteger:self.eventType forKey:@"eventType"];
    [coder encodeInt64:self.bytesIn forKey:@"bytesIn"];
    [coder encodeInt64:self.bytesOut forKey:@"bytesOut"];
    [coder encodeObject:self.direction forKey:@"direction"];
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        self.sourceIP = [coder decodeObjectOfClass:[NSString class] forKey:@"sourceIP"];
        self.destinationIP = [coder decodeObjectOfClass:[NSString class] forKey:@"destinationIP"];
        self.sourcePort = [coder decodeIntForKey:@"sourcePort"];
        self.destinationPort = [coder decodeIntForKey:@"destinationPort"];
        self.protocol = [coder decodeIntForKey:@"protocol"];
        self.processID = [coder decodeIntForKey:@"processID"];
        self.processName = [coder decodeObjectOfClass:[NSString class] forKey:@"processName"];
        self.processPath = [coder decodeObjectOfClass:[NSString class] forKey:@"processPath"];
        self.userID = [coder decodeIntForKey:@"userID"];
        self.groupID = [coder decodeIntForKey:@"groupID"];
        self.timestamp = [coder decodeObjectOfClass:[NSDate class] forKey:@"timestamp"];
        self.eventType = [coder decodeIntegerForKey:@"eventType"];
        self.bytesIn = [coder decodeInt64ForKey:@"bytesIn"];
        self.bytesOut = [coder decodeInt64ForKey:@"bytesOut"];
        self.direction = [coder decodeObjectOfClass:[NSString class] forKey:@"direction"];
    }
    return self;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"ScreechNetworkFlow: %@:%d -> %@:%d (%@) PID:%d Process:%@",
            self.sourceIP, self.sourcePort, self.destinationIP, self.destinationPort,
            self.protocol == IPPROTO_TCP ? @"TCP" : @"UDP", self.processID, self.processName];
}

@end

@implementation ScreechProcessEvent

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeInt:self.processID forKey:@"processID"];
    [coder encodeInt:self.parentProcessID forKey:@"parentProcessID"];
    [coder encodeObject:self.processName forKey:@"processName"];
    [coder encodeObject:self.processPath forKey:@"processPath"];
    [coder encodeInt:self.userID forKey:@"userID"];
    [coder encodeInt:self.groupID forKey:@"groupID"];
    [coder encodeObject:self.timestamp forKey:@"timestamp"];
    [coder encodeInteger:self.eventType forKey:@"eventType"];
    [coder encodeObject:self.arguments forKey:@"arguments"];
    [coder encodeInt:self.exitCode forKey:@"exitCode"];
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        self.processID = [coder decodeIntForKey:@"processID"];
        self.parentProcessID = [coder decodeIntForKey:@"parentProcessID"];
        self.processName = [coder decodeObjectOfClass:[NSString class] forKey:@"processName"];
        self.processPath = [coder decodeObjectOfClass:[NSString class] forKey:@"processPath"];
        self.userID = [coder decodeIntForKey:@"userID"];
        self.groupID = [coder decodeIntForKey:@"groupID"];
        self.timestamp = [coder decodeObjectOfClass:[NSDate class] forKey:@"timestamp"];
        self.eventType = [coder decodeIntegerForKey:@"eventType"];
        self.arguments = [coder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class], [NSString class], nil] forKey:@"arguments"];
        self.exitCode = [coder decodeIntForKey:@"exitCode"];
    }
    return self;
}

- (NSString *)description {
    NSString *eventTypeString;
    switch (self.eventType) {
        case ScreechEventTypeProcessExec:
            eventTypeString = @"EXEC";
            break;
        case ScreechEventTypeProcessFork:
            eventTypeString = @"FORK";
            break;
        case ScreechEventTypeProcessExit:
            eventTypeString = @"EXIT";
            break;
        default:
            eventTypeString = @"UNKNOWN";
            break;
    }
    
    return [NSString stringWithFormat:@"ScreechProcessEvent: %@ PID:%d Process:%@ Path:%@",
            eventTypeString, self.processID, self.processName, self.processPath];
}

@end

@implementation ScreechFileEvent

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeInt:self.processID forKey:@"processID"];
    [coder encodeInt:self.parentProcessID forKey:@"parentProcessID"];
    [coder encodeObject:self.processName forKey:@"processName"];
    [coder encodeObject:self.processPath forKey:@"processPath"];
    [coder encodeInt:self.userID forKey:@"userID"];
    [coder encodeInt:self.groupID forKey:@"groupID"];
    [coder encodeObject:self.timestamp forKey:@"timestamp"];
    [coder encodeInteger:self.eventType forKey:@"eventType"];
    [coder encodeObject:self.filePath forKey:@"filePath"];
    [coder encodeObject:self.fileName forKey:@"fileName"];
    [coder encodeInt64:self.fileSize forKey:@"fileSize"];
    [coder encodeInt:self.fileMode forKey:@"fileMode"];
    [coder encodeObject:self.fileOperation forKey:@"fileOperation"];
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        self.processID = [coder decodeIntForKey:@"processID"];
        self.parentProcessID = [coder decodeIntForKey:@"parentProcessID"];
        self.processName = [coder decodeObjectOfClass:[NSString class] forKey:@"processName"];
        self.processPath = [coder decodeObjectOfClass:[NSString class] forKey:@"processPath"];
        self.userID = [coder decodeIntForKey:@"userID"];
        self.groupID = [coder decodeIntForKey:@"groupID"];
        self.timestamp = [coder decodeObjectOfClass:[NSDate class] forKey:@"timestamp"];
        self.eventType = [coder decodeIntegerForKey:@"eventType"];
        self.filePath = [coder decodeObjectOfClass:[NSString class] forKey:@"filePath"];
        self.fileName = [coder decodeObjectOfClass:[NSString class] forKey:@"fileName"];
        self.fileSize = [coder decodeInt64ForKey:@"fileSize"];
        self.fileMode = [coder decodeIntForKey:@"fileMode"];
        self.fileOperation = [coder decodeObjectOfClass:[NSString class] forKey:@"fileOperation"];
    }
    return self;
}

- (NSString *)description {
    NSString *eventTypeString;
    switch (self.eventType) {
        case ScreechEventTypeFileCreate:
            eventTypeString = @"FILE_CREATE";
            break;
        case ScreechEventTypeFileWrite:
            eventTypeString = @"FILE_WRITE";
            break;
        case ScreechEventTypeFileRead:
            eventTypeString = @"FILE_READ";
            break;
        default:
            eventTypeString = @"FILE_UNKNOWN";
            break;
    }
    
    return [NSString stringWithFormat:@"ScreechFileEvent: %@ PID:%d Process:%@ File:%@ Size:%llu",
            eventTypeString, self.processID, self.processName, self.filePath, self.fileSize];
}

@end

@implementation ScreechLogger

+ (os_log_t)screechLog {
    static os_log_t log;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        log = os_log_create("com.screech", "general");
    });
    return log;
}

+ (void)logInfo:(NSString *)message {
    os_log_info([self screechLog], "%{public}@", message);
    NSLog(@"[SCREECH INFO] %@", message);
}

+ (void)logError:(NSString *)message {
    os_log_error([self screechLog], "%{public}@", message);
    NSLog(@"[SCREECH ERROR] %@", message);
}

+ (void)logDebug:(NSString *)message {
    os_log_debug([self screechLog], "%{public}@", message);
    NSLog(@"[SCREECH DEBUG] %@", message);
}

+ (void)writeToFile:(NSString *)filename content:(NSString *)content {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    NSString *filePath = [documentsDirectory stringByAppendingPathComponent:filename];
    
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
    if (fileHandle == nil) {
        // File doesn't exist, create it
        [[NSFileManager defaultManager] createFileAtPath:filePath contents:nil attributes:nil];
        fileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
    }
    
    if (fileHandle != nil) {
        [fileHandle seekToEndOfFile];
        NSString *timestampedContent = [NSString stringWithFormat:@"[%@] %@\n", 
                                       [[NSDate date] description], content];
        [fileHandle writeData:[timestampedContent dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    }
}

@end
