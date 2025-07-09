## Overview

Each node adds a 2-slot plaintext vector:
- Slot 2i: `xi * di`  
- Slot 2i+1: `xi * si + di`  
Where:
- `xi`: per-node multiplier (public)
- `si`: per-node secret (shared only with server)
- `di`: the current sensor reading

The server later:
- Decrypts the ciphertext  
- Removes the random mask `R`  
- Recovers `di` via modular inverse of `xi`  
- Verifies `Qi ≟ xi * si + di`

## How to build

Make sure HElib is installed with CMake support:

```bash
git clone https://github.com/homenc/HElib
cd HElib && mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$HOME/HElib/install
make -j && make install
```

Then clone this project and build:

```bash
cd ~/projects
git clone https://github.com/imincloudnine/fhe-ascheme.git
cd fhe-ascheme
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH=$HOME/HElib/install
make
```

## How to run

```bash
./fhe_a
```

You should see output like:

```
Verified readings:
Node 0: 1234
Node 1: 4321
...
```

## Notes

* Currently uses `n = 4` nodes by default (adjustable in code)
* Ciphertext uses batching; ensure slot count ≥ 2n
* Uses HElib's BGV scheme with plaintext modulus `p = 4999`

