#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <thread>
#include <chrono>
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/PcapFilter.h"

class PacketPrinter {
private:
    pcpp::PcapLiveDevice* m_device;

    void printPacketHex(const pcpp::Packet& packet) {
        const uint8_t* data = packet.getRawPacket()->getRawData();
        size_t dataLen = packet.getRawPacket()->getRawDataLen();

        for (size_t i = 0; i < dataLen; i += 16) {
            // Print offset
            std::cout << std::hex << std::setw(4) << std::setfill('0') << i << ": ";

            // Print hex values
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < dataLen) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') 
                              << static_cast<int>(data[i + j]) << " ";
                } else {
                    std::cout << "   ";
                }
            }

            // Print ASCII representation
            std::cout << " ";
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < dataLen) {
                    char c = data[i + j];
                    std::cout << (isprint(c) ? c : '.');
                }
            }
            std::cout << std::endl;
        }
        std::cout << std::endl;
    }

    bool isExternalIP(const std::string& ip) {
        // Exclude private network ranges
        return !(
            ip.substr(0, 8) == "192.168." ||  // Class C private
            ip.substr(0, 7) == "10.0.0." ||   // Class A private
            ip.substr(0, 12) == "172.16.0.0"  // Class B private
        );
    }

public:
    PacketPrinter(const std::string& deviceName) {
        m_device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(deviceName);
        if (!m_device) {
            throw std::runtime_error("Network device not found");
        }
    }

    void startCapture() {
        // Open device in promiscuous mode
        if (!m_device->open()) {
            throw std::runtime_error("Could not open device");
        }

        // Get the IP address of this device and use it in the filter
        std::string deviceIP = m_device->getIPv4Address().toString();
        std::string bpfFilter = "not igmp and not arp and not port 22 and host " + deviceIP + " and not port 5353 and not net 17.57.144.0/24 and not udp port 67 and not udp port 68";
        
        std::cout << "Using BPF filter: " << bpfFilter << std::endl;
        
        if (!m_device->setFilter(bpfFilter)) {
            throw std::runtime_error("Failed to set BPF filter");
        }

        pcpp::RawPacketVector packetVec;
        m_device->startCapture(packetVec);

        std::this_thread::sleep_for(std::chrono::seconds(60));

        m_device->stopCapture();

        for (auto rawPacket : packetVec) {
            pcpp::Packet parsedPacket(rawPacket);
            std::cout << "Packet Capture:" << std::endl;
            // Verify IPv4 layer
            pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            if (!ipLayer) continue;
            std::string srcIP = ipLayer->getSrcIPAddress().toString();
            std::string dstIP = ipLayer->getDstIPAddress().toString();
            std::cout << "Source: " << srcIP << std::endl;
            std::cout << "Destination: " << dstIP << std::endl;
            printPacketHex(parsedPacket);
        }
    }
    
    void stopCapture() {
        m_device->stopCapture();
        m_device->close();
    }
};

int main() {
    try {
        // Requires root/sudo privileges
        // Look for an interface with an IP on a private network
        pcpp::PcapLiveDevice* dev = nullptr;
        auto devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

        for (auto device : devices) {
            auto ip = device->getIPv4Address().toString();
            std::cout << "Checking interface: " << device->getName() << " with IP: " << ip << std::endl;
            
            // Check for private network ranges
            if (ip.substr(0, 3) == "10." ||           // 10.x.x.x
                ip.substr(0, 4) == "172." ||          // 172.x.x.x  
                ip.substr(0, 4) == "192.") {          // 192.x.x.x
                std::cout << "Selected interface: " << device->getName() << " (" << ip << ")" << std::endl;
                dev = device;
                break;
            }
        }

        if (!dev) {
            std::cerr << "Cannot find any suitable network interface" << std::endl;
            return 1;
        }

        if (!dev->open()) {
            std::cerr << "Cannot open device" << std::endl;
            return 1;
        }

        PacketPrinter printer(dev->getName());

        std::cout << "Starting packet capture on " << dev->getName() << "..." << std::endl;
        printer.startCapture();

        dev->close();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
