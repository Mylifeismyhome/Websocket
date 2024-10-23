# WebSocket Library in C++11

## Overview

This repository contains a WebSocket library written in C++11, providing both a C API and a C++ API for easy integration into various projects.
The library is designed to facilitate secure and unsecured WebSocket connections, utilizing [mbedTLS](https://tls.mbed.org/) for secure communication. 

## Features

- **C API and C++ API**: Provides both C and C++ interfaces for flexibility and ease of use.
- **Secure Connections**: Utilizes mbedTLS to support secure WebSocket (wss) connections.
- **Unsecured Connections**: Supports both secured (wss) and unsecured (ws) WebSocket connections.
- **CMake Build System**: Easily build the library using CMake.

## Requirements

- C++11 or later
- CMake 3.0 or later

## Installation

### Building from Source

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Mylifeismyhome/Websocket.git
   cd Websocket
   mkdir build
   cd build
   cmake -DCMAKE_CXX_FLAGS="-m64" -DENABLE_C_API=ON -DENABLE_CPP_API=ON -DBUILD_SHARED=ON -DBUILD_STATIC=ON -DEXAMPLE_C_API=ON ../CMakeLists.txt
   make
