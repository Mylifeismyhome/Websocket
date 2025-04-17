### About

This repository provides a RFC 6455–compliant WebSocket implementation with both C and C++ APIs, enabling effortless integration into a wide range of projects. It supports both unencrypted (WS) and encrypted (WSS) connections, using [mbedTLS](https://tls.mbed.org/) to secure data over TLS.

## Features

- **Dual C and C++ Interfaces**  
  Flexible APIs in both C and C++ to suit your projects language preferences.

- **WS and WSS Support**  
  Full support for standard WebSocket (WS) and secure WebSocket (WSS) connections, with TLS handled by mbedTLS.

- **CMake-Based Build**  
  Easily build and integrate the library using CMake’s familiar workflow.

- **Optional Doxygen Documentation**  
  Generate comprehensive API docs with Doxygen for quick reference and onboarding.

## Supported Extensions

- **permessage-deflate**: Supports the permessage-deflate extension for message compression over WebSocket connections, enhancing efficiency and performance.

## Limitations

- **Sec-WebSocket-Protocol**: Not handled.

## Requirements

- C++11 or later
- CMake 3.0 or later
- **[optional]** Doxygen

## Building from Source

```bash
git clone https://github.com/Mylifeismyhome/Websocket.git
cd ./Websocket
mkdir ./build
cd ./build
cmake -DCMAKE_CXX_FLAGS="-m64" -DENABLE_C_API=ON -DENABLE_CPP_API=ON -DBUILD_SHARED=ON -DBUILD_STATIC=ON -DEXAMPLE_C_API=ON ./../CMakeLists.txt
make
```

## Building documentation

```bash
doxygen ./DoxyFile
```
