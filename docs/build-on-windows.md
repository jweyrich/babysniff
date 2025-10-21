# Building babysniff on Windows

## Prerequisites

1. **Visual Studio 2019 or later** with C++ development tools
   - Or **Visual Studio Build Tools 2019+**
   - Or **MinGW-w64** with GCC

2. **CMake 3.10 or later**
   - Download from https://cmake.org/download/
   - Make sure it's added to your PATH

3. **Administrator privileges** - Required for raw socket operations

## Building with Visual Studio

1. Open a **Developer Command Prompt** or **PowerShell** as Administrator

2. Navigate to the babysniff directory:
   ```cmd
   cd path\to\babysniff
   ```

3. Create a build directory:
   ```cmd
   mkdir build
   cd build
   ```

4. Generate Visual Studio project files:
   ```cmd
   cmake .. -G "Visual Studio 16 2019" -A x64
   ```
   (Use "Visual Studio 17 2022" for VS 2022)

5. Build the project:
   ```cmd
   cmake --build . --config Release
   ```

6. The executable will be in `build\Release\babysniff.exe`

### Alternative: Building with CMAKE GUI

1. Open CMake GUI
2. Set source directory to the babysniff folder
3. Set build directory to `babysniff/build`
4. Click "Configure" and select your Visual Studio version
5. Click "Generate" to create project files
6. Open `build/babysniff.sln` in Visual Studio and build

## Building with MinGW

1. Open a command prompt as Administrator

2. Navigate to the babysniff directory and create build directory:
   ```cmd
   cd path\to\babysniff
   mkdir build
   cd build
   ```

3. Generate MinGW Makefiles:
   ```cmd
   cmake .. -G "MinGW Makefiles"
   ```

4. Build:
   ```cmd
   mingw32-make
   ```

## Usage on Windows

**Important**: Raw sockets on Windows require Administrator privileges.

1. Open **Command Prompt as Administrator**

2. Run babysniff:
   ```cmd
   babysniff.exe -i "Ethernet" "tcp"
   ```

### Finding network interface names

On Windows, network interfaces have descriptive names. You can find them using:

```cmd
netsh interface show interface
```

Common interface names:
- "Ethernet"
- "Wi-Fi"
- "Local Area Connection"

### BPF filtering examples

The Windows implementation supports the same BPF filter syntax as Linux and BSD:

```cmd
# Capture only TCP traffic
babysniff.exe -i "Ethernet" "tcp"

# Capture traffic to/from specific host
babysniff.exe -i "Ethernet" "host 192.168.1.1"

# Capture traffic on specific port
babysniff.exe -i "Ethernet" "port 80"

# Capture DNS traffic
babysniff.exe -i "Ethernet" "dns"

# Capture ICMP ping traffic
babysniff.exe -i "Ethernet" "icmp"
```

## Windows-specific limitations

1. **Datalink layer**: Windows raw sockets only capture IP packets (Layer 3), not Ethernet frames (Layer 2)
   - No access to MAC addresses, VLAN tags, or ARP packets
   - BPF filters automatically adjust offsets for raw IP packets
   - ARP filtering is not supported on Windows
   - Limited to IPv4 on most Windows versions

2. **BPF filtering**: Only emulated BPF is supported (no kernel-level native BPF)
   - All packet filtering is done in user space
   - Filtering performance will be slower than native BPF on Linux and BSD

3. **Administrator requirements**: Raw socket operations require Administrator privileges
   - Use "Run as Administrator" for Command Prompt or PowerShell
   - Alternative: Use `pkexec` or similar privilege escalation tools

4. **Interface discovery**: Uses the IP Helper API for interface enumeration
   - Supports both adapter names and friendly names
   - Automatically resolves interface IP addresses for binding

5. **Socket behavior**: Windows-specific socket handling
   - Uses `ioctlsocket()` instead of `fcntl()` for non-blocking mode
   - Uses `closesocket()` instead of `close()` for socket cleanup
   - Different error codes and handling via `WSAGetLastError()`

## Troubleshooting

- **"Administrator privileges required"**: Run Command Prompt as Administrator
- **"socket(SOCK_RAW) failed"**: Make sure you're running as Administrator
- **"WSAIoctl(SIO_RCVALL) failed"**: Your network adapter may not support promiscuous mode
- **Build errors**: Make sure you have the Windows SDK installed with Visual Studio
- **Interface not found**: Use `netsh interface show interface` to list valid interface names
- **BPF filter failures**: Check filter syntax - Windows supports the same filters as Linux but with automatic datalink type detection
- **Missing protocol captures**: Remember that ARP and other Layer 2 protocols are not available on Windows raw sockets

## Dependencies

The Windows implementation uses only standard Windows APIs:
- **Winsock2** (`ws2_32.lib`): Core networking functionality
- **IP Helper API** (`iphlpapi.lib`): Interface enumeration and management
- **Windows SDK**: Standard system headers and libraries

Third-party libraries like WinPcap/Npcap/libpcap are not required!
