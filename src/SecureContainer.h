#ifndef _SECURECONTAINER_H_
#define _SECURECONTAINER_H_

#include "AuthenticatedEncryption.h"
#include <string>
#include <vector>
#include <map>

class SecureContainer {
private:
    AuthenticatedEncryption* authEnc;
    
    static constexpr uint32_t MAGIC_NUMBER = 0x41455343;
    static constexpr uint16_t VERSION = 1;
    
    struct Header {
        uint32_t magic;
        uint16_t version;
        uint32_t metadataSize;
        uint32_t dataSize;
        uint64_t timestamp;
    };
    
    std::vector<unsigned char> serializeMetadata(
        const std::map<std::string, std::string>& metadata);
    
    std::map<std::string, std::string> deserializeMetadata(
        const std::vector<unsigned char>& data);

public:
    SecureContainer();
    
    ~SecureContainer();
    
    std::vector<unsigned char> createContainer(
        const std::vector<unsigned char>& data,
        const std::vector<unsigned char>& key,
        const std::map<std::string, std::string>& metadata = {});
    
    std::vector<unsigned char> extractFromContainer(
        const std::vector<unsigned char>& container,
        const std::vector<unsigned char>& key,
        std::map<std::string, std::string>& metadata);
    
    bool saveToFile(const std::vector<unsigned char>& container,
                   const std::string& filename);
    
    std::vector<unsigned char> loadFromFile(const std::string& filename);
    
    bool verifyContainer(const std::vector<unsigned char>& container,
                        const std::vector<unsigned char>& key);
    
    std::map<std::string, std::string> getMetadata(
        const std::vector<unsigned char>& container,
        const std::vector<unsigned char>& key);
    
    struct ContainerInfo {
        uint32_t version;
        uint64_t timestamp;
        size_t totalSize;
        size_t dataSize;
        size_t metadataSize;
    };
    
    ContainerInfo getContainerInfo(const std::vector<unsigned char>& container);
    
    std::vector<unsigned char> createContainerFromFile(
        const std::string& inputFile,
        const std::vector<unsigned char>& key,
        const std::map<std::string, std::string>& metadata = {});
    
    bool extractContainerToFile(
        const std::vector<unsigned char>& container,
        const std::vector<unsigned char>& key,
        const std::string& outputFile,
        std::map<std::string, std::string>& metadata);
};

#endif
