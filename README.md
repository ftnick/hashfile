# hashfile
## Build
```powershell
cmake -S . -B build
cmake --build build --config Debug
```
## Usage
```powershell
./build/Debug/hashfile.exe verify path\to\file --sha256 <checksum>
./build/Debug/hashfile.exe verify path\to\file --blake2b <checksum>
```
