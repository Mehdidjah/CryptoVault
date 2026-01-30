cmake_minimum_required(VERSION 3.5)

project(CryptoVault CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCE_FILES 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/AES.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/PBKDF2.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Padding.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/AES_CTR.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Base64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/HMAC.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/KeyManager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/FileEncryption.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/StreamCipher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/AuthenticatedEncryption.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/SecureContainer.cpp
)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(${PROJECT_NAME} ${SOURCE_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})

# Build feature demo
add_executable(feature_demo ${CMAKE_CURRENT_SOURCE_DIR}/examples/feature_demo.cpp)
target_link_libraries(feature_demo ${PROJECT_NAME})
