# StupidVNC: The Stupid VNC Server Implementation

StupidVNC is a lightweight and stupid implementation of VNC (Virtual Network Computing) server implementation
written in C++. It aims to provide a basic yet functional VNC server that can be used for integrating VNC/RFB
in your application.

## Features

- **Basic Functionality**: StupidVNC offers essential functionality for hosting a VNC server, including framebuffer updates, client-to-server messaging, and basic authentication.
- **Encoding Support**: It only supports Raw and ZRLE encodings.
- **WebSocket support**: For using fx. noVNC to access the server from a browser.


## Getting Started

1. **Prerequisites**: Ensure you have the necessary dependencies installed, including OpenSSL and zlib.
2. **Building**: Use cmake to build it.
3. **Integration**: Look in lsdtest.cpp and x11stupidvncserver.cpp on how to integrate StupidVNC in to your applicatio.
