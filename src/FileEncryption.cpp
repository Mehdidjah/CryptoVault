#include "FileEncryption.h"
#include <fstream>
#include <iostream>
#include <random>
#include <sys/stat.h>

FileEncryption::FileEncryption(const AESKeyLength keyLength) : keyLength(keyLength) {
    aes = new AES(keyLength);
}

FileEncryption::~FileEncryption() {
    delete aes;
}

std::vector<unsigned char> FileEncryption::readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Error reading file: " + filename);
    }
    
    return buffer;
}

void FileEncryption::writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot create file: " + filename);
    }
    
    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        throw std::runtime_error("Error writing file: " + filename);
    }
}

bool FileEncryption::encryptFile(const std::string& inputFile,
                                const std::string& outputFile,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv) {
    try {
        std::vector<unsigned char> plaintext = readFile(inputFile);
        
        std::vector<unsigned char> padded = Padding::addPKCS7(plaintext);
        
        std::vector<unsigned char> ciphertext = aes->EncryptCBC(padded, key, iv);
        
        writeFile(outputFile, ciphertext);
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        return false;
    }
}

bool FileEncryption::decryptFile(const std::string& inputFile,
                                const std::string& outputFile,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv) {
    try {
        std::vector<unsigned char> ciphertext = readFile(inputFile);
        
        std::vector<unsigned char> padded = aes->DecryptCBC(ciphertext, key, iv);
        
        std::vector<unsigned char> plaintext = Padding::removePKCS7(padded);
        
        writeFile(outputFile, plaintext);
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Decryption error: " << e.what() << std::endl;
        return false;
    }
}

std::vector<unsigned char> FileEncryption::encryptFileWithIV(const std::string& inputFile,
                                                            const std::string& outputFile,
                                                            const std::vector<unsigned char>& key) {
    try {
        std::vector<unsigned char> iv(16);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < 16; i++) {
            iv[i] = static_cast<unsigned char>(dis(gen));
        }
        
        std::vector<unsigned char> plaintext = readFile(inputFile);
        std::vector<unsigned char> padded = Padding::addPKCS7(plaintext);
        std::vector<unsigned char> ciphertext = aes->EncryptCBC(padded, key, iv);
        
        std::vector<unsigned char> output;
        output.reserve(16 + ciphertext.size());
        output.insert(output.end(), iv.begin(), iv.end());
        output.insert(output.end(), ciphertext.begin(), ciphertext.end());
        
        writeFile(outputFile, output);
        
        return iv;
    } catch (const std::exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        return std::vector<unsigned char>();
    }
}

bool FileEncryption::decryptFileWithIV(const std::string& inputFile,
                                      const std::string& outputFile,
                                      const std::vector<unsigned char>& key) {
    try {
        std::vector<unsigned char> data = readFile(inputFile);
        
        if (data.size() < 16) {
            throw std::runtime_error("File too small to contain IV");
        }
        
        std::vector<unsigned char> iv(data.begin(), data.begin() + 16);
        
        std::vector<unsigned char> ciphertext(data.begin() + 16, data.end());
        
        std::vector<unsigned char> padded = aes->DecryptCBC(ciphertext, key, iv);
        
        std::vector<unsigned char> plaintext = Padding::removePKCS7(padded);
        
        writeFile(outputFile, plaintext);
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Decryption error: " << e.what() << std::endl;
        return false;
    }
}

size_t FileEncryption::getFileSize(const std::string& filename) {
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : 0;
}

bool FileEncryption::fileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}
