#import "SystemFramework.h"
#import <CommonCrypto/CommonCrypto.h>
#import <dlfcn.h>

// Obfuscated service identifiers using generic system-like names
NSString * const SystemProviderMachServiceName = @"com.apple.system.analytics.provider";
NSString * const SystemAnalyticsServiceBundleID = @"com.apple.systemanalytics.service";

// ROT13 encoding for basic string obfuscation
static NSString *rot13(NSString *input) {
    NSMutableString *result = [NSMutableString stringWithCapacity:input.length];
    for (NSUInteger i = 0; i < input.length; i++) {
        unichar c = [input characterAtIndex:i];
        if (c >= 'a' && c <= 'z') {
            c = ((c - 'a' + 13) % 26) + 'a';
        } else if (c >= 'A' && c <= 'Z') {
            c = ((c - 'A' + 13) % 26) + 'A';
        }
        [result appendFormat:@"%C", c];
    }
    return result;
}

// Simple XOR encryption for log content
static NSData *xorEncrypt(NSData *data, NSString *key) {
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [NSMutableData dataWithLength:data.length];
    
    for (NSUInteger i = 0; i < data.length; i++) {
        ((char*)result.mutableBytes)[i] = ((char*)data.bytes)[i] ^ ((char*)keyData.bytes)[i % keyData.length];
    }
    return result;
}

@implementation SystemNetworkFlow

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.srcAddr forKey:@"sa"];
    [coder encodeObject:self.dstAddr forKey:@"da"];
    [coder encodeInteger:self.srcEndpoint forKey:@"se"];
    [coder encodeInteger:self.dstEndpoint forKey:@"de"];
    [coder encodeInteger:self.transportProtocol forKey:@"tp"];
    [coder encodeInteger:self.processIdentifier forKey:@"pi"];
    [coder encodeObject:self.processLabel forKey:@"pl"];
    [coder encodeObject:self.processLocation forKey:@"ploc"];
    [coder encodeInteger:self.userIdentifier forKey:@"ui"];
    [coder encodeInteger:self.groupIdentifier forKey:@"gi"];
    [coder encodeObject:self.eventTimestamp forKey:@"et"];
    [coder encodeInteger:self.analyticsType forKey:@"at"];
    [coder encodeInt64:self.inboundBytes forKey:@"ib"];
    [coder encodeInt64:self.outboundBytes forKey:@"ob"];
    [coder encodeObject:self.flowDirection forKey:@"fd"];
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        self.srcAddr = [coder decodeObjectForKey:@"sa"];
        self.dstAddr = [coder decodeObjectForKey:@"da"];
        self.srcEndpoint = [coder decodeIntegerForKey:@"se"];
        self.dstEndpoint = [coder decodeIntegerForKey:@"de"];
        self.transportProtocol = [coder decodeIntegerForKey:@"tp"];
        self.processIdentifier = [coder decodeIntForKey:@"pi"];
        self.processLabel = [coder decodeObjectForKey:@"pl"];
        self.processLocation = [coder decodeObjectForKey:@"ploc"];
        self.userIdentifier = [coder decodeIntForKey:@"ui"];
        self.groupIdentifier = [coder decodeIntForKey:@"gi"];
        self.eventTimestamp = [coder decodeObjectForKey:@"et"];
        self.analyticsType = [coder decodeIntegerForKey:@"at"];
        self.inboundBytes = [coder decodeInt64ForKey:@"ib"];
        self.outboundBytes = [coder decodeInt64ForKey:@"ob"];
        self.flowDirection = [coder decodeObjectForKey:@"fd"];
    }
    return self;
}

@end

@implementation SystemProcessActivity

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeInteger:self.processIdentifier forKey:@"pi"];
    [coder encodeInteger:self.parentProcessIdentifier forKey:@"ppi"];
    [coder encodeObject:self.processLabel forKey:@"pl"];
    [coder encodeObject:self.processLocation forKey:@"ploc"];
    [coder encodeInteger:self.userIdentifier forKey:@"ui"];
    [coder encodeInteger:self.groupIdentifier forKey:@"gi"];
    [coder encodeObject:self.eventTimestamp forKey:@"et"];
    [coder encodeInteger:self.analyticsType forKey:@"at"];
    [coder encodeObject:self.launchParameters forKey:@"lp"];
    [coder encodeInteger:self.terminationCode forKey:@"tc"];
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        self.processIdentifier = [coder decodeIntForKey:@"pi"];
        self.parentProcessIdentifier = [coder decodeIntForKey:@"ppi"];
        self.processLabel = [coder decodeObjectForKey:@"pl"];
        self.processLocation = [coder decodeObjectForKey:@"ploc"];
        self.userIdentifier = [coder decodeIntForKey:@"ui"];
        self.groupIdentifier = [coder decodeIntForKey:@"gi"];
        self.eventTimestamp = [coder decodeObjectForKey:@"et"];
        self.analyticsType = [coder decodeIntegerForKey:@"at"];
        self.launchParameters = [coder decodeObjectForKey:@"lp"];
        self.terminationCode = [coder decodeIntForKey:@"tc"];
    }
    return self;
}

@end

@implementation SystemFileActivity

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeInteger:self.processIdentifier forKey:@"pi"];
    [coder encodeInteger:self.parentProcessIdentifier forKey:@"ppi"];
    [coder encodeObject:self.processLabel forKey:@"pl"];
    [coder encodeObject:self.processLocation forKey:@"ploc"];
    [coder encodeInteger:self.userIdentifier forKey:@"ui"];
    [coder encodeInteger:self.groupIdentifier forKey:@"gi"];
    [coder encodeObject:self.eventTimestamp forKey:@"et"];
    [coder encodeInteger:self.analyticsType forKey:@"at"];
    [coder encodeObject:self.targetPath forKey:@"tp"];
    [coder encodeObject:self.targetName forKey:@"tn"];
    [coder encodeInt64:self.dataSize forKey:@"ds"];
    [coder encodeInteger:self.accessMode forKey:@"am"];
    [coder encodeObject:self.operationType forKey:@"ot"];
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        self.processIdentifier = [coder decodeIntForKey:@"pi"];
        self.parentProcessIdentifier = [coder decodeIntForKey:@"ppi"];
        self.processLabel = [coder decodeObjectForKey:@"pl"];
        self.processLocation = [coder decodeObjectForKey:@"ploc"];
        self.userIdentifier = [coder decodeIntForKey:@"ui"];
        self.groupIdentifier = [coder decodeIntForKey:@"gi"];
        self.eventTimestamp = [coder decodeObjectForKey:@"et"];
        self.analyticsType = [coder decodeIntegerForKey:@"at"];
        self.targetPath = [coder decodeObjectForKey:@"tp"];
        self.targetName = [coder decodeObjectForKey:@"tn"];
        self.dataSize = [coder decodeInt64ForKey:@"ds"];
        self.accessMode = [coder decodeIntegerForKey:@"am"];
        self.operationType = [coder decodeObjectForKey:@"ot"];
    }
    return self;
}

@end

@implementation SystemLoggingService

// Dynamic log file path generation to avoid predictable names
+ (NSString *)generateLogPath:(NSString *)processName {
    NSString *homeDir = NSHomeDirectory();
    NSString *timestamp = [@(time(NULL)) stringValue];
    NSString *hash = [self hashString:[processName stringByAppendingString:timestamp]];
    
    // Use system-like directory names
    NSString *logDir = [homeDir stringByAppendingPathComponent:@".system_analytics"];
    [[NSFileManager defaultManager] createDirectoryAtPath:logDir withIntermediateDirectories:YES attributes:nil error:nil];
    
    return [logDir stringByAppendingPathComponent:[NSString stringWithFormat:@"analytics_%@.log", [hash substringToIndex:8]]];
}

+ (NSString *)hashString:(NSString *)input {
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(cStr, (CC_LONG)strlen(cStr), digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return output;
}

+ (void)logInformation:(NSString *)message {
    // Only log if debug environment variable is set
    if (getenv("SYS_ANALYTICS_DEBUG")) {
        NSLog(@"[SYS-INFO] %@", message);
    }
}

+ (void)logFailure:(NSString *)message {
    if (getenv("SYS_ANALYTICS_DEBUG")) {
        NSLog(@"[SYS-ERROR] %@", message);
    }
}

+ (void)logDiagnostics:(NSString *)message {
    if (getenv("SYS_ANALYTICS_VERBOSE")) {
        NSLog(@"[SYS-DEBUG] %@", message);
    }
}

+ (void)appendToAnalyticsFile:(NSString *)filename content:(NSString *)content {
    NSString *logPath = [self generateLogPath:filename];
    
    // Encrypt log content with simple XOR
    NSData *contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = xorEncrypt(contentData, @"sys_analytics_key_2024");
    
    // Add timestamp and obfuscate process name
    NSString *timestamp = [[NSDateFormatter new] stringFromDate:[NSDate date]];
    NSString *obfuscatedName = rot13(filename);
    NSString *logEntry = [NSString stringWithFormat:@"[%@] %@: %@\n", timestamp, obfuscatedName, [[NSString alloc] initWithData:encryptedData encoding:NSUTF8StringEncoding]];
    
    NSData *logData = [logEntry dataUsingEncoding:NSUTF8StringEncoding];
    
    // Append to file or create if doesn't exist
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:logPath];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:logData];
        [fileHandle closeFile];
    } else {
        [logData writeToFile:logPath atomically:YES];
    }
}

@end
