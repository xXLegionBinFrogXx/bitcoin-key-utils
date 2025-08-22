[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CMake](https://img.shields.io/badge/CMake-3.24+-blue.svg)](https://cmake.org/)
[![C++23](https://img.shields.io/badge/C++-23-blue?logo=cplusplus)](https://en.wikipedia.org/wiki/C%2B%2B23)

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
cd bitcoin-key-utils
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

target_link_libraries(your_target PRIVATE BitcoinKeyUtils::static)
# or:
target_link_libraries(your_target PRIVATE BitcoinKeyUtils::shared)
```

Include the header in your C++ code:

```cpp
#include <bitcoin_key_utils.h>
```

### Example

The `examples/demo.cpp` file demonstrates basic usage. Below are code snippets that show how to use the library for common tasks:

#### Encoding a Private Key to WIF

```cpp
#include "bitcoin_key_utils.h"
using namespace BitcoinKeyUtils;

std::string privHex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
auto privateKey = HexToBytes(privHex);
auto wifCompressed = EncodeWIF(privateKey, true);
if (wifCompressed) {
    std::cout << "WIF (compressed): " << *wifCompressed << std::endl;
    // Expected: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
} else {
    std::cerr << "WIF encoding failed: " << wifCompressed.error().message << std::endl;
}
```

#### Generating a Public Key Hash

```cpp
#include "bitcoin_key_utils.h"
using namespace BitcoinKeyUtils;

std::string pubHexCom = "02D0DE0AAEAEFAD02B8BDC8A01A1B8B11C696BD3D66A2C5F10780D95B7DF42645C";
auto pubKey = HexToBytes(pubHexCom);
auto pubKeyHashExp = HashRIPEMD160SHA256(pubKey);
if (pubKeyHashExp) {
    std::cout << "PubKey HASH160 (hex): " << BytesToHex(*pubKeyHashExp) << std::endl;
    // Expected: d9351dcbad5b8f3b8bfa2f2cdc85c28118ca9326
} else {
    std::cerr << "Hash160 failed: " << pubKeyHashExp.error().message << std::endl;
}
```

#### Generating P2PKH and P2WPKH Addresses

```cpp
#include "bitcoin_key_utils.h"
using namespace BitcoinKeyUtils;

auto pubKeyHash = *HashRIPEMD160SHA256(pubKey);
auto p2pkh = GenerateP2PKHAddress(pubKeyHash);
if (p2pkh) {
    std::cout << "P2PKH address: " << *p2pkh << std::endl;
    // Expected: 1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK
}

auto p2wpkh = GenerateP2WPKHAddress(pubKeyHash);
if (p2wpkh) {
    std::cout << "P2WPKH (bech32) address: " << *p2wpkh << std::endl;
    // Expected: bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd
}
```

To build and run the full demo, enable the `BUILD_EXAMPLES` option:

```bash
cmake .. -DBUILD_EXAMPLES=ON
cmake --build .
./demo
```


## Error Codes

All recoverable errors are reported via the `ErrorCode` enum. Each API that returns `std::expected` uses these codes to explain why the operation failed.

| Error Code                      | Meaning                                           | Typical Cause                                                      |
| ------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------ |
| **`InvalidPrivateKeySize`**     | The private key length is not 32 bytes.           | Passing in a malformed or truncated private key.                   |
| **`Base58CheckEncodingFailed`** | Failed to encode or decode Base58Check.           | Input data is invalid or checksum mismatch.                        |
| **`EmptyData`**                 | Input data is empty where non-empty was required. | Attempting to hash or encode an empty vector.                      |
| **`Hash160SizeMismatch`**       | Hash160 must be exactly 20 bytes.                 | Wrongly sized data provided to a function expecting a pubkey hash. |
| **`InvalidPubKeyHashSize`**     | Public key hash is not 20 bytes.                  | Supplying incorrectly sized key material to address generation.    |
| **`InvalidHRP`**                | Human-readable prefix for Bech32 is invalid.      | Using an unsupported or empty HRP string.                          |
| **`Bech32BitConversionFailed`** | Conversion from 8-bit to 5-bit groups failed.     | Internal encoding error or invalid input data.                     |
| **`Bech32EncodingFailed`**      | Final Bech32 string encoding failed.              | Input could not represented in Bech32 format.                      |


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
