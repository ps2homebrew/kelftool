
cmake_minimum_required(VERSION 3.10)

# set the project name
project(kelftool)

# add the executable
include_directories(src)
find_package(OpenSSL REQUIRED)
add_executable(kelftool 
    src/kelf.cpp
    src/kelftool.cpp
    src/keystore.cpp
)
target_link_libraries(kelftool OpenSSL::SSL)
target_compile_definitions(kelftool PRIVATE DEBUG=1)