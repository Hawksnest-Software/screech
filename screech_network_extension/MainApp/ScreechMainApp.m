#import "ScreechMainApp.h"
#import <libproc.h>
#import <sys/proc_info.h>
#import <signal.h>
#import <bsm/libbsm.h>
#import <netinet/in.h>

// Global reference for signal handling
static ScreechMainApp *globalMainApp = nil;

void signalHandler(int signal) {
    if (signal == SIGINT && globalMainApp) {
        [ScreechLogger logInfo:@"Received SIGINT, stopping monitoring..."];
        globalMainApp.shouldStop = YES;
    }
}

@implementation ScreechMainApp

#pragma mark - Initialization

- (instancetype)init {
    self = [super init];
    if (self) {
        self.configuration = [[NSMutableDictionary alloc] init];
        self.configuration[@"monitoringEnabled"] = @YES;
        self.shouldStop = NO;
        self.networkExtensionActive = NO;
        self.endpointSecurityActive = NO;
        
        // Set global reference for signal handling
        globalMainApp = self;
        signal(SIGINT, signalHandler);
        
        [ScreechLogger logInfo:@"ScreechMainApp initialized"];
    }
    return self;
}

- (void)dealloc {
    [self stopMonitoring];
    globalMainApp = nil;
    [super dealloc];
}

#pragma mark - Main Control Methods

- (BOOL)startMonitoring {
    [ScreechLogger logInfo:@"Starting Screech monitoring with Network Extension + Endpoint Security"];
    
    // Setup Network Extension first
    [self setupNetworkExtension];
    
    // Setup Endpoint Security
    if (![self setupEndpointSecurity]) {
        [ScreechLogger logError:@"Failed to setup Endpoint Security"];
        return NO;
    }
    
    [ScreechLogger logInfo:@"Screech monitoring started successfully"];
    [ScreechLogger logInfo:@"Network monitoring: Using Network Extension framework"];
    [ScreechLogger logInfo:@"Process monitoring: Using Endpoint Security framework"];
    [ScreechLogger logInfo:@"File monitoring: Using Endpoint Security framework"];
    [ScreechLogger logInfo:@"Output format: Compatible with Linux eBPF screech"];
    
    return YES;
}

- (void)stopMonitoring {
    [ScreechLogger logInfo:@"Stopping Screech monitoring"];
    
    [self stopNetworkExtension];
    [self teardownEndpointSecurity];
    
    [ScreechLogger logInfo:@"Screech monitoring stopped"];
}

- (void)runMainLoop {
    [ScreechLogger logInfo:@"Monitoring network connections and process events... Press Ctrl+C to stop."];
    
    NSRunLoop *runLoop = [NSRunLoop currentRunLoop];
    
    while (!self.shouldStop) {
        @autoreleasepool {
            [runLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
    }
    
    [ScreechLogger logInfo:@"Main loop exited"];
}

#pragma mark - Network Extension Management

- (void)setupNetworkExtension {
    [ScreechLogger logInfo:@"Setting up Network Extension"];
    
    self.filterManager = [NEFilterManager sharedManager];
    
    [self.filterManager loadFromPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
        if (error) {
            [ScreechLogger logError:[NSString stringWithFormat:@"Failed to load filter configuration: %@", error.localizedDescription]];
            return;
        }
        
        [self startNetworkExtension];
    }];
}

- (void)startNetworkExtension {
    // Create filter configuration for macOS
    NEFilterProviderConfiguration *providerConfig = [[NEFilterProviderConfiguration alloc] init];
    providerConfig.filterSockets = YES;
    providerConfig.filterPackets = NO; // We're doing flow-level monitoring
    
    // Set the correct data provider bundle identifier for macOS
    providerConfig.filterDataProviderBundleIdentifier = @"com.screech.networkextension";
    
    // On macOS, we use NEConfiguration instead of NEFilterManagerConfiguration
    self.filterManager.localizedDescription = @"Screech Network Monitor";
    self.filterManager.providerConfiguration = providerConfig;
    self.filterManager.enabled = YES;
    
    [self.filterManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
        if (error) {
            [ScreechLogger logError:[NSString stringWithFormat:@"Failed to save filter configuration: %@", error.localizedDescription]];
            return;
        }
        
        [ScreechLogger logInfo:@"Network Extension configuration saved"];
        self.networkExtensionActive = YES;
        
        // Establish XPC connection to extension
        [self establishExtensionConnection];
    }];
}

- (void)stopNetworkExtension {
    if (!self.networkExtensionActive) {
        return;
    }
    
    [ScreechLogger logInfo:@"Stopping Network Extension"];
    
    self.filterManager.enabled = NO;
    [self.filterManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
        if (error) {
            [ScreechLogger logError:[NSString stringWithFormat:@"Failed to disable filter: %@", error.localizedDescription]];
        } else {
            [ScreechLogger logInfo:@"Network Extension stopped"];
        }
    }];
    
    [self.extensionConnection invalidate];
    self.extensionConnection = nil;
    self.networkExtensionActive = NO;
}

- (void)establishExtensionConnection {
    self.extensionConnection = [[NSXPCConnection alloc] initWithMachServiceName:ScreechNetworkExtensionMachServiceName options:0];
    
    self.extensionConnection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ScreechMainAppCommunication)];
    self.extensionConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ScreechExtensionCommunication)];
    self.extensionConnection.exportedObject = self;
    
    ScreechMainApp *mainApp = self;  // Avoid retain cycle by using weak reference pattern
    self.extensionConnection.invalidationHandler = ^{
        [ScreechLogger logError:@"Extension XPC connection invalidated"];
        mainApp.extensionConnection = nil;
    };
    
    self.extensionConnection.interruptionHandler = ^{
        [ScreechLogger logError:@"Extension XPC connection interrupted"];
    };
    
    [self.extensionConnection resume];
    [ScreechLogger logInfo:@"Extension XPC connection established"];
}

#pragma mark - Endpoint Security Management

- (BOOL)setupEndpointSecurity {
    [ScreechLogger logInfo:@"Setting up Endpoint Security"];
    
    // Create ES client with handler block
    es_handler_block_t handler = ^(es_client_t * _Nonnull client, const es_message_t * _Nonnull message) {
        (void)client; // Suppress unused parameter warning
        [self processEndpointSecurityEvent:message];
    };
    
    es_new_client_result_t result = es_new_client(&_esClient, handler);
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        [ScreechLogger logError:[NSString stringWithFormat:@"Failed to create Endpoint Security client: %d", result]];
        [ScreechLogger logError:@"Make sure the application has proper entitlements and SIP is configured."];
        return NO;
    }
    
    // Subscribe to process and file events
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CREATE,    // File creation
        ES_EVENT_TYPE_NOTIFY_WRITE,     // File writes
        ES_EVENT_TYPE_NOTIFY_OPEN       // File opens (for read detection)
    };
    
    es_return_t subscribe_result = es_subscribe(_esClient, events, sizeof(events) / sizeof(events[0]));
    if (subscribe_result != ES_RETURN_SUCCESS) {
        [ScreechLogger logError:[NSString stringWithFormat:@"Failed to subscribe to ES events: %d", subscribe_result]];
        es_delete_client(_esClient);
        _esClient = NULL;
        return NO;
    }
    
    self.endpointSecurityActive = YES;
    [ScreechLogger logInfo:@"Endpoint Security setup completed"];
    return YES;
}

- (void)teardownEndpointSecurity {
    if (!self.endpointSecurityActive || _esClient == NULL) {
        return;
    }
    
    [ScreechLogger logInfo:@"Tearing down Endpoint Security"];
    
    es_delete_client(_esClient);
    _esClient = NULL;
    self.endpointSecurityActive = NO;
    
    [ScreechLogger logInfo:@"Endpoint Security torn down"];
}

#pragma mark - Event Processing

- (void)processNetworkFlow:(ScreechNetworkFlow *)flow {
    // Log network event in Linux eBPF compatible format
    [self logNetworkEvent:flow];
}

- (void)processEndpointSecurityEvent:(const es_message_t *)message {
    if (!message) return;
    
    ScreechProcessEvent *processEvent = [[ScreechProcessEvent alloc] init];
    processEvent.timestamp = [NSDate date];
    
    // Get process information
    pid_t pid = audit_token_to_pid(message->process->audit_token);
    processEvent.processID = pid;
    processEvent.processName = [self getProcessNameForPID:pid];
    processEvent.processPath = [self getProcessPathForPID:pid];
    
    // Get process credentials
    struct proc_bsdinfo procInfo;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) > 0) {
        processEvent.userID = procInfo.pbi_uid;
        processEvent.groupID = procInfo.pbi_gid;
        processEvent.parentProcessID = procInfo.pbi_ppid;
    }
    
    // Handle different event types
    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            processEvent.eventType = ScreechEventTypeProcessExec;
            // Extract command line arguments using ES API helper functions
            uint32_t argCount = es_exec_arg_count(&message->event.exec);
            if (argCount > 0) {
                NSMutableArray *args = [[NSMutableArray alloc] init];
                for (uint32_t i = 0; i < argCount; i++) {
                    es_string_token_t token = es_exec_arg(&message->event.exec, i);
                    NSString *arg = [[NSString alloc] initWithBytes:token.data length:token.length encoding:NSUTF8StringEncoding];
                    if (arg) {
                        [args addObject:arg];
                    }
                }
                processEvent.arguments = [args copy];
            }
            break;
            
        case ES_EVENT_TYPE_NOTIFY_FORK:
            processEvent.eventType = ScreechEventTypeProcessFork;
            break;
            
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            processEvent.eventType = ScreechEventTypeProcessExit;
            processEvent.exitCode = message->event.exit.stat;
            break;
            
        case ES_EVENT_TYPE_NOTIFY_CREATE:
        case ES_EVENT_TYPE_NOTIFY_WRITE:
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            // Handle file events separately
            [self processFileEventFromEndpointSecurity:message];
            return;
            
        default:
            return; // Skip unhandled events
    }
    
    // Log process event
    [self logProcessEvent:processEvent];
    
    // Send to network extension for correlation
    if (self.extensionConnection) {
        id<ScreechMainAppCommunication> remoteProxy = [self.extensionConnection remoteObjectProxy];
        [remoteProxy processEventDetected:processEvent];
    }
}

#pragma mark - Process Information Helpers

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

#pragma mark - File Event Processing

- (void)processFileEventFromEndpointSecurity:(const es_message_t *)message {
    if (!message) return;
    
    ScreechFileEvent *fileEvent = [[ScreechFileEvent alloc] init];
    fileEvent.timestamp = [NSDate date];
    
    // Get process information
    pid_t pid = audit_token_to_pid(message->process->audit_token);
    fileEvent.processID = pid;
    fileEvent.processName = [self getProcessNameForPID:pid];
    fileEvent.processPath = [self getProcessPathForPID:pid];
    
    // Get process credentials
    struct proc_bsdinfo procInfo;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) > 0) {
        fileEvent.userID = procInfo.pbi_uid;
        fileEvent.groupID = procInfo.pbi_gid;
        fileEvent.parentProcessID = procInfo.pbi_ppid;
    }
    
    // Extract file information based on event type
    NSString *filePath = nil;
    uint64_t fileSize = 0;
    mode_t fileMode = 0;
    
    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_CREATE: {
            fileEvent.eventType = ScreechEventTypeFileCreate;
            fileEvent.fileOperation = @"CREATE";
            
            // Get file path from create event
            if (message->event.create.destination.new_path.filename.data) {
                es_string_token_t filename = message->event.create.destination.new_path.filename;
                NSString *fileName = [[NSString alloc] initWithBytes:filename.data 
                                                             length:filename.length 
                                                           encoding:NSUTF8StringEncoding];
                
                // Get directory path from the parent directory
                if (message->event.create.destination.new_path.dir && 
                    message->event.create.destination.new_path.dir->path.data) {
                    es_string_token_t dirPathToken = message->event.create.destination.new_path.dir->path;
                    NSString *dirPathStr = [[NSString alloc] initWithBytes:dirPathToken.data 
                                                                   length:dirPathToken.length 
                                                                 encoding:NSUTF8StringEncoding];
                    filePath = [dirPathStr stringByAppendingPathComponent:fileName];
                } else {
                    filePath = fileName; // Fallback to just filename if directory unavailable
                }
                fileEvent.fileName = fileName;
            }
            fileMode = message->event.create.destination.new_path.mode;
            break;
        }
            
        case ES_EVENT_TYPE_NOTIFY_WRITE: {
            fileEvent.eventType = ScreechEventTypeFileWrite;
            fileEvent.fileOperation = @"WRITE";
            
            // Get file path from write event
            if (message->event.write.target && message->event.write.target->path.data) {
                es_string_token_t pathToken = message->event.write.target->path;
                filePath = [[NSString alloc] initWithBytes:pathToken.data 
                                                   length:pathToken.length 
                                                 encoding:NSUTF8StringEncoding];
                fileEvent.fileName = [filePath lastPathComponent];
            }
            break;
        }
            
        case ES_EVENT_TYPE_NOTIFY_OPEN: {
            fileEvent.eventType = ScreechEventTypeFileRead;
            fileEvent.fileOperation = @"READ";
            
            // Get file path from open event (used for read detection)
            if (message->event.open.file && message->event.open.file->path.data) {
                es_string_token_t pathToken = message->event.open.file->path;
                filePath = [[NSString alloc] initWithBytes:pathToken.data 
                                                   length:pathToken.length 
                                                 encoding:NSUTF8StringEncoding];
                fileEvent.fileName = [filePath lastPathComponent];
            }
            break;
        }
            
        default:
            return; // Unhandled event type
    }
    
    // Set file information
    fileEvent.filePath = filePath ? filePath : @"unknown";
    fileEvent.fileSize = fileSize;
    fileEvent.fileMode = fileMode;
    
    // Filter out system files and temporary files to reduce noise
    if ([self shouldIgnoreFileEvent:fileEvent]) {
        return;
    }
    
    // Process and log the file event
    [self processFileEvent:fileEvent];
}

- (void)processFileEvent:(ScreechFileEvent *)event {
    // Log file event in greppable format
    [self logFileEvent:event];
}

- (BOOL)shouldIgnoreFileEvent:(ScreechFileEvent *)event {
    // Filter out common system and temporary files to reduce noise
    NSString *filePath = event.filePath;
    if (!filePath || filePath.length == 0) {
        return YES;
    }
    
    // Skip system directories and common temp files
    NSArray *ignorePrefixes = @[
        @"/System/",
        @"/usr/",
        @"/var/log/",
        @"/private/var/",
        @"/tmp/",
        @"/Library/Caches/",
        @"/Library/Logs/"
    ];
    
    for (NSString *prefix in ignorePrefixes) {
        if ([filePath hasPrefix:prefix]) {
            return YES;
        }
    }
    
    // Skip hidden files and certain extensions
    NSString *fileName = event.fileName;
    if ([fileName hasPrefix:@"."] || 
        [fileName hasSuffix:@".DS_Store"] ||
        [fileName hasSuffix:@".log"] ||
        [fileName hasSuffix:@".tmp"]) {
        return YES;
    }
    
    return NO;
}

#pragma mark - Logging (Linux eBPF Compatible Format)

- (void)logNetworkEvent:(ScreechNetworkFlow *)flow {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *timestamp = [formatter stringFromDate:flow.timestamp];
    
    NSString *protocolString = (flow.protocol == IPPROTO_TCP) ? @"TCP" : @"UDP";
    
    // Create log filename based on process name (matching Linux eBPF format)
    NSString *logFileName = [NSString stringWithFormat:@"screech_%@.log", flow.processName];
    if (flow.processName.length == 0) {
        logFileName = @"screech_unknown_process.log";
    }
    
    // Write greppable log entry (matching Linux eBPF format)
    NSString *logEntry = [NSString stringWithFormat:@"[%@] CONN|%@ %@:%d->%@:%d|PID:%d|PROC:%@|UID:%d|PATH:%@",
                         timestamp, protocolString, flow.sourceIP, flow.sourcePort, 
                         flow.destinationIP, flow.destinationPort, flow.processID, 
                         flow.processName, flow.userID, flow.processPath];
    
    [self writeToLogFile:logFileName content:logEntry];
    
    // Also log to console (matching Linux eBPF format)
    NSLog(@"[%@] NEW CONNECTION: %@ %@:%d -> %@:%d (PID: %d, Process: %@)",
          timestamp, protocolString, flow.sourceIP, flow.sourcePort,
          flow.destinationIP, flow.destinationPort, flow.processID, flow.processName);
}

- (void)logProcessEvent:(ScreechProcessEvent *)event {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *timestamp = [formatter stringFromDate:event.timestamp];
    
    NSString *eventTypeString;
    switch (event.eventType) {
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
    
    // Create log filename based on process name
    NSString *logFileName = [NSString stringWithFormat:@"screech_%@.log", event.processName];
    if (event.processName.length == 0) {
        logFileName = @"screech_unknown_process.log";
    }
    
    // Write greppable log entry
    NSString *logEntry = [NSString stringWithFormat:@"[%@] EVENT|%@|PID:%d|PROC:%@|UID:%d|PATH:%@",
                         timestamp, eventTypeString, event.processID, event.processName, 
                         event.userID, event.processPath];
    
    [self writeToLogFile:logFileName content:logEntry];
    
    // Also log to console
    NSLog(@"[%@] %@: %@ (PID: %d)", timestamp, eventTypeString, event.processName, event.processID);
}

- (void)logFileEvent:(ScreechFileEvent *)event {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *timestamp = [formatter stringFromDate:event.timestamp];
    
    NSString *eventTypeString;
    switch (event.eventType) {
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
    
    // Create log filename based on process name
    NSString *logFileName = [NSString stringWithFormat:@"screech_%@.log", event.processName];
    if (event.processName.length == 0) {
        logFileName = @"screech_unknown_process.log";
    }
    
    // Write greppable log entry for file events
    NSString *logEntry = [NSString stringWithFormat:@"[%@] FILE|%@|PID:%d|PROC:%@|UID:%d|FILE:%@|SIZE:%llu|MODE:%o|PATH:%@",
                         timestamp, eventTypeString, event.processID, event.processName, 
                         event.userID, event.fileName, event.fileSize, event.fileMode, event.filePath];
    
    [self writeToLogFile:logFileName content:logEntry];
    
    // Also log to console with readable format
    NSLog(@"[%@] %@: %@ -> %@ (PID: %d, Process: %@, Size: %llu bytes)",
          timestamp, eventTypeString, event.processName, event.filePath, 
          event.processID, event.processName, event.fileSize);
}

- (void)writeToLogFile:(NSString *)filename content:(NSString *)content {
    // Get Documents directory path
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths firstObject];
    NSString *filePath = [documentsDirectory stringByAppendingPathComponent:filename];
    
    // Create file if it doesn't exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:filePath]) {
        [fileManager createFileAtPath:filePath contents:nil attributes:nil];
    }
    
    // Append content
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        NSString *contentWithNewline = [content stringByAppendingString:@"\n"];
        [fileHandle writeData:[contentWithNewline dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    }
}

#pragma mark - ScreechExtensionCommunication Protocol

- (void)networkFlowDetected:(ScreechNetworkFlow *)flow {
    [self processNetworkFlow:flow];
}

- (void)extensionStarted {
    [ScreechLogger logInfo:@"Network Extension started"];
}

- (void)extensionStopped {
    [ScreechLogger logInfo:@"Network Extension stopped"];
}

- (void)extensionError:(NSError *)error {
    [ScreechLogger logError:[NSString stringWithFormat:@"Network Extension error: %@", error.localizedDescription]];
}

@end
