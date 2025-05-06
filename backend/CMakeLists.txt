cmake_minimum_required(VERSION 3.10)
project(OnlineVote)

set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

add_executable(server src/main.cpp)
target_include_directories(server PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(server PRIVATE SQLite::SQLite3 OpenSSL::Crypto pthread)
