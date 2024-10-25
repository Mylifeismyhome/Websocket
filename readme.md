## About

This repository implements WebSocket functionality based on RFC6455, providing both C and C++ APIs for seamless integration into diverse projects.
The library is designed to facilitate secure and unsecured WebSocket connections, utilizing [mbedTLS](https://tls.mbed.org/) for secure communication. 

## Features

- **C and C++ APIs**: Offers both C and C++ interfaces for flexibility and ease of integration.
- **Secure and Unsecured WebSocket Connections**: Supports secure WebSocket (WSS) using mbedTLS, as well as standard unsecured WebSocket (WS) connections.
- **CMake Build System**: Simplifies building and integrating the library with CMake.

## Limitations

- **RSV1 Flag**: Compression (e.g., permessage-deflate) is not yet supported but will be added in the future.
- **Sec-WebSocket-Protocol**: Not currently handled.
- **Sec-WebSocket-Extension**: Not currently handled.

## Requirements

- C++11 or later
- CMake 3.0 or later
- **[optional]** Doxygen

## Building from Source

```bash
git clone https://github.com/Mylifeismyhome/Websocket.git
cd Websocket
mkdir build
cd build
cmake -DCMAKE_CXX_FLAGS="-m64" -DENABLE_C_API=ON -DENABLE_CPP_API=ON -DBUILD_SHARED=ON -DBUILD_STATIC=ON -DEXAMPLE_C_API=ON ../CMakeLists.txt
make
```

## Building documentation

```bash
doxygen DoxyFile
```
