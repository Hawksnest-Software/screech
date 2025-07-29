//
// NetworkMonitor.mm - Simple libpcap-based network monitoring
//
#include "NetworkMonitor.h"
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <thread>
#include <atomic>

static std::atomic<bool> monitoring_active{false};
static pcap_t *pcap_handle = nullptr;
static std::thread monitor_thread;

// Packet handler callback
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Basic packet info logging
    std::cout << "Captured packet: " << pkthdr->len << " bytes" << std::endl;
    
    // TODO: Add packet parsing and filtering logic here
    // For now, just log basic info
}

bool start_network_monitoring(const char *interface) {
    if (monitoring_active.load()) {
        return false; // Already running
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open network interface for packet capture
    pcap_handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == nullptr) {
        std::cerr << "Error opening interface " << interface << ": " << errbuf << std::endl;
        return false;
    }
    
    monitoring_active.store(true);
    
    // Start monitoring in separate thread
    monitor_thread = std::thread([]() {
        while (monitoring_active.load()) {
            pcap_loop(pcap_handle, 1, packet_handler, nullptr);
        }
    });
    
    return true;
}

bool stop_network_monitoring() {
    if (!monitoring_active.load()) {
        return false; // Not running
    }
    
    monitoring_active.store(false);
    
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }
    
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }
    
    return true;
}

bool is_network_monitoring_active() {
    return monitoring_active.load();
}
