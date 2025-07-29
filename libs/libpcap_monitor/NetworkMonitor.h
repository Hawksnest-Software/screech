//
// NetworkMonitor.h - Simple libpcap network monitoring interface
//
#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

// Simple C interface for libpcap network monitoring
bool start_network_monitoring(const char *interface);
bool stop_network_monitoring(void);
bool is_network_monitoring_active(void);

#ifdef __cplusplus
}
#endif

#endif // NETWORK_MONITOR_H
