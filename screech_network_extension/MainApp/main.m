#import <Foundation/Foundation.h>
#import "ScreechMainApp.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Check if running as root (required for Endpoint Security)
        if (geteuid() != 0) {
            NSLog(@"This program requires root privileges for Endpoint Security.");
            NSLog(@"Please run with sudo.");
            return 1;
        }
        
        ScreechMainApp *mainApp = [[ScreechMainApp alloc] init];
        
        if (![mainApp startMonitoring]) {
            NSLog(@"Failed to start monitoring");
            return 1;
        }
        
        // Run the main loop
        [mainApp runMainLoop];
        
        // Cleanup
        [mainApp stopMonitoring];
        
        return 0;
    }
}
