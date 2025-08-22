# BitcoinKeyUtils

BitcoinKeyUtils is a C++ library for handling operations related to Bitcoin. Includes Encoding/Decoding for Wallet Import Format (WIF), Base58, Bech32 operations. It uses curated list of Bitcoin Core source files for functionality.

## Features

- Generate and manipulate Bitcoin private keys and public key hashes
- Support for Base58 and Bech32 encoding/decoding
- Conversion to and from Wallet Import Format (WIF)
- Generate Bitcoin addresses
- Supports both static and shared library builds
- Built with modern C++23 standards

## Prerequisites

- CMake 3.24+
- C++23 compatible compiler
- Bash (for running the Bitcoin Core update script on Unix-like systems)
- Git (for fetching Bitcoin Core sources)

## Building the Library

### Clone the Repository

```bash
git clone <repository-url>
cd BitcoinKeyUtils
```

### Configure and Build

Create a build directory and run CMake to configure the project. The `BUILD_SHARED` and `BUILD_STATIC` options control whether to build shared and/or static libraries (**both enabled by default**).

```bash
mkdir build
cd build
cmake .. -DBUILD_SHARED=ON -DBUILD_STATIC=ON  # use flags to control which library type to built
cmake --build .
```

This will build:
- Static library: `libbitcoin_key_utils.a` (or `.lib` on Windows)
- Shared library: `libbitcoin_key_utils.so` (or `.dll` on Windows)
- Demo executable: `demo` (in `build/bin`, if `BUILD_EXAMPLES=ON`)

### Install the Library

To install the library and headers to your system:

```bash
cmake --install .
```

This installs:
- Libraries to `${CMAKE_INSTALL_LIBDIR}` (e.g., `/usr/local/lib`)
- Headers to `${CMAKE_INSTALL_INCLUDEDIR}/bitcoin_key_utils` and `${CMAKE_INSTALL_INCLUDEDIR}/bitcoin_core`
- CMake package config to `${CMAKE_INSTALL_LIBDIR}/cmake/BitcoinKeyUtils`

## Usage

### Including in Your Project

To use BitcoinKeyUtils in a CMake project, link against either the static or shared library:

```cmake
find_package(BitcoinKeyUtils REQUIRED)
target_link_libraries(your_target PRIVATE BitcoinKeyUtils::Static)  # or BitcoinKeyUtils::Shared
```

Include the header in your C++ code:

```cpp
#include <bitcoin_key_utils.h>
```

### Example

The `examples/demo.cpp` file demonstrates basic usage. To build and run the demo, enable the `BUILD_EXAMPLES` option:

```bash
cmake .. -DBUILD_EXAMPLES=ON
cmake --build .
./build/bin/demo
```

## Dependencies

The library uses curated sources from Bitcoin Core, which are automatically fetched or updated by the `scripts/update_bitcoin_core.sh` script during the build process. The following Bitcoin Core components are included:
- Base58 encoding/decoding
- Bech32 encoding/decoding
- SHA256 and RIPEMD160 cryptographic functions
- Utility functions for string handling

## Directory Structure

- `include/`: Public header files for the library
- `src/`: Library source files
- `external/bitcoin-core/`: Curated Bitcoin Core sources
- `examples/`: Demo application
- `scripts/`: Utility scripts (e.g., `update_bitcoin_core.sh`)
- `cmake/`: CMake package configuration files

## License

This project is licensed under the MIT License. See the LICENSE file for details.
This project incorporates code from Bitcoin Core, licensed under the MIT License.
See the LICENSE/COPYING file in the Bitcoin Core repository for details.
