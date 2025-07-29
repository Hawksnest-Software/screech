#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import "ScreechFilterDataProvider.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Network Extensions are managed by the system
        // The entry point should just run the run loop
        [NEProvider startSystemExtensionMode];
    }
    return 0;
}
