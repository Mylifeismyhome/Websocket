# WebSocket Library

## Overview

This repository contains a WebSocket library that offers both C and C++ APIs for easy integration into various projects.
The library is designed to facilitate secure and unsecured WebSocket connections, utilizing [mbedTLS](https://tls.mbed.org/) for secure communication. 

## Features

- **C API and C++ API**: Provides both C and C++ interfaces for flexibility and ease of use.
- **Secure and Unsecured Connections**: Supports both secure WebSocket (WSS) connections using mbedTLS and unsecured WebSocket (WS) connections.
- **CMake Build System**: Easily build the library using CMake.

## Requirements

- C++11 or later
- CMake 3.0 or later

### Building from Source

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Mylifeismyhome/Websocket.git
   cd Websocket
   mkdir build
   cd build
   cmake -DCMAKE_CXX_FLAGS="-m64" -DENABLE_C_API=ON -DENABLE_CPP_API=ON -DBUILD_SHARED=ON -DBUILD_STATIC=ON -DEXAMPLE_C_API=ON ../CMakeLists.txt
   make
