# DES
This is a implementation of Data Encription Standard (DES).  
**Note:** DES has been deprecated as it is unsafe.

## Dependencies
This project uses no external dependencies.  
This project uses C++14 standard.

## Building
Building with Cmake consists of configuring the project, and then building it.
```bash
mkdir build/
cd build
cmake ..
cmake --build .
```

## Tests
The project contains a few test vectors. To run the test vectors first configure the project with `BUILD_TESTS`, then build.
```bash
cmake -DBUILD_TESTS:BOOL=TRUE ..
cmake --build .
```
Then run the command.
```bash
ctest -C Debug
```

## Reference
https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf  
https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/Triple-Des-2-Key-128-64.unverified.test-vectors  
https://www.nayuki.io/page/des-cipher-internals-in-excel