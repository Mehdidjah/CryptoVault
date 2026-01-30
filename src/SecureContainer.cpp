#include "SecureContainer.h"
#include <fstream>
#include <ctime>
#include <cstring>
#include <sstream>

SecureContainer::SecureContainer() {
    authEnc = new AuthenticatedEncryption(AESKeyLength::AES_256);
}

SecureContainer::~SecureContainer() {
    delete authEnc;
}

std::vector<unsigned char> SecureContainer::serializeMetadata(
    const std::map<std::string, std::string>& metadata) {
    
    std::stringstream ss;
    
    uint32_t count = metadata.size();
    ss.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    for (const auto& pair : metadata) {
        uint32_t keyLen = pair.first.length();
        ss.write(reinterpret_cast<const char*>(&keyLen), sizeof(keyLen));
        ss.write(pair.first.c_str(), keyLen);
        
        uint32_t valueLen = pair.second.length();
        ss.write(reinterpret_cast<const char*>(&valueLen), sizeof(valueLen));
        ss.write(pair.second.c_str(), valueLen);
    }
    
    std::string str = ss.str();
    return std::vector<unsigned char>(str.begin(), str.end());
}

std::map<std::string, std::string> SecureContainer::deserializeMetadata(
    const std::vector<unsigned char>& data) {
    
    std::map<std::string, std::string> metadata;
    size_t pos = 0;
    
    if (data.size() < sizeof(uint32_t)) {
        return metadata;
    }
    
    uint32_t count;
    memcpy(&count, data.data() + pos, sizeof(count));
    pos += sizeof(count);
    
    for (uint32_t i = 0; i < count && pos < data.size(); i++) {
        if (pos + sizeof(uint32_t) > data.size()) break;
        uint32_t keyLen;
        memcpy(&keyLen, data.data() + pos, sizeof(keyLen));
        pos += sizeof(keyLen);
        
        if (pos + keyLen > data.size()) break;
        std::string key(reinterpret_cast<const char*>(data.data() + pos), keyLen);
        pos += keyLen;
        
        if (pos + sizeof(uint32_t) > data.size()) break;
        uint32_t valueLen;
        memcpy(&valueLen, data.data() + pos, sizeof(valueLen));
        pos += sizeof(valueLen);
        
        if (pos + valueLen > data.size()) break;
        std::string value(reinterpret_cast<const char*>(data.data() + pos), valueLen);
        pos += valueLen;
        
        metadata[key] = value;
    }
    
    return metadata;
}

std::vector<unsigned char> SecureContainer::createContainer(
    const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& key,
    const std::map<std::string, std::string>& metadata) {
    
    std::vector<unsigned char> metadataBytes = serializeMetadata(metadata);
    
    std::vector<unsigned char> encryptedData = authEnc->encrypt(data, key);
    
    Header header;
    header.magic = MAGIC_NUMBER;
    header.version = VERSION;
    header.metadataSize = metadataBytes.size();
    header.dataSize = encryptedData.size();
    header.timestamp = static_cast<uint64_t>(std::time(nullptr));
    
    std::vector<unsigned char> container;
    container.reserve(sizeof(Header) + metadataBytes.size() + encryptedData.size());
    
    const unsigned char* headerBytes = reinterpret_cast<const unsigned char*>(&header);
    container.insert(container.end(), headerBytes, headerBytes + sizeof(Header));
    
    container.insert(container.end(), metadataBytes.begin(), metadataBytes.end());
    
    container.insert(container.end(), encryptedData.begin(), encryptedData.end());
    
    return container;
}

std::vector<unsigned char> SecureContainer::extractFromContainer(
    const std::vector<unsigned char>& container,
    const std::vector<unsigned char>& key,
    std::map<std::string, std::string>& metadata) {
    
    if (container.size() < sizeof(Header)) {
        throw std::runtime_error("Invalid container: too small");
    }
    
    Header header;
    memcpy(&header, container.data(), sizeof(Header));
    
    if (header.magic != MAGIC_NUMBER) {
        throw std::runtime_error("Invalid container: bad magic number");
    }
    
    if (header.version != VERSION) {
        throw std::runtime_error("Unsupported container version");
    }
    
    size_t expectedSize = sizeof(Header) + header.metadataSize + header.dataSize;
    if (container.size() < expectedSize) {
        throw std::runtime_error("Invalid container: size mismatch");
    }
    
    std::vector<unsigned char> metadataBytes(
        container.begin() + sizeof(Header),
        container.begin() + sizeof(Header) + header.metadataSize);
    metadata = deserializeMetadata(metadataBytes);
    
    std::vector<unsigned char> encryptedData(
        container.begin() + sizeof(Header) + header.metadataSize,
        container.begin() + sizeof(Header) + header.metadataSize + header.dataSize);
    
    return authEnc->decrypt(encryptedData, key);
}

bool SecureContainer::saveToFile(const std::vector<unsigned char>& container,
                                const std::string& filename) {
    try {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }
        file.write(reinterpret_cast<const char*>(container.data()), container.size());
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<unsigned char> SecureContainer::loadFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> container(fileSize);
    file.read(reinterpret_cast<char*>(container.data()), fileSize);
    
    return container;
}

bool SecureContainer::verifyContainer(const std::vector<unsigned char>& container,
                                     const std::vector<unsigned char>& key) {
    try {
        std::map<std::string, std::string> metadata;
        extractFromContainer(container, key, metadata);
        return true;
    } catch (...) {
        return false;
    }
}

std::map<std::string, std::string> SecureContainer::getMetadata(
    const std::vector<unsigned char>& container,
    const std::vector<unsigned char>& key) {
    
    if (container.size() < sizeof(Header)) {
        return {};
    }
    
    Header header;
    memcpy(&header, container.data(), sizeof(Header));
    
    if (header.magic != MAGIC_NUMBER || container.size() < sizeof(Header) + header.metadataSize) {
        return {};
    }
    
    std::vector<unsigned char> metadataBytes(
        container.begin() + sizeof(Header),
        container.begin() + sizeof(Header) + header.metadataSize);
    
    return deserializeMetadata(metadataBytes);
}

SecureContainer::ContainerInfo SecureContainer::getContainerInfo(
    const std::vector<unsigned char>& container) {
    
    ContainerInfo info = {0};
    
    if (container.size() < sizeof(Header)) {
        return info;
    }
    
    Header header;
    memcpy(&header, container.data(), sizeof(Header));
    
    if (header.magic != MAGIC_NUMBER) {
        return info;
    }
    
    info.version = header.version;
    info.timestamp = header.timestamp;
    info.totalSize = container.size();
    info.dataSize = header.dataSize;
    info.metadataSize = header.metadataSize;
    
    return info;
}

std::vector<unsigned char> SecureContainer::createContainerFromFile(
    const std::string& inputFile,
    const std::vector<unsigned char>& key,
    const std::map<std::string, std::string>& metadata) {
    
    std::ifstream file(inputFile, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + inputFile);
    }
    
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> data(fileSize);
    file.read(reinterpret_cast<char*>(data.data()), fileSize);
    
    std::map<std::string, std::string> fullMetadata = metadata;
    if (fullMetadata.find("filename") == fullMetadata.end()) {
        size_t lastSlash = inputFile.find_last_of("/\\");
        std::string filename = (lastSlash != std::string::npos) 
            ? inputFile.substr(lastSlash + 1) : inputFile;
        fullMetadata["filename"] = filename;
    }
    
    return createContainer(data, key, fullMetadata);
}

bool SecureContainer::extractContainerToFile(
    const std::vector<unsigned char>& container,
    const std::vector<unsigned char>& key,
    const std::string& outputFile,
    std::map<std::string, std::string>& metadata) {
    
    try {
        std::vector<unsigned char> data = extractFromContainer(container, key, metadata);
        
        std::ofstream file(outputFile, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return true;
    } catch (...) {
        return false;
    }
}
