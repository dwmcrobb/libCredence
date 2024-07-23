# Dwm::Credence C++ Class Library
This class library may be used for secure, authenticated network
communication over TCP.  The main three classes are 
[Dwm::Credence::Peer](https://www.mcplex.net/Software/Documentation/libDwmCredence/classDwm_1_1Credence_1_1Peer.html),
[Dwm::Credence::KeyStash](https://www.mcplex.net/Software/Documentation/libDwmCredence/classDwm_1_1Credence_1_1KeyStash.html)
and 
[Dwm::Credence::KnownKeys](https://www.mcplex.net/Software/Documentation/libDwmCredence/classDwm_1_1Credence_1_1KnownKeys.html).
Utilizing just these three classes, it is relatively easy to create secure TCP
applications.

## History

## Platforms
FreeBSD, linux (Debian-based systems including Ubuntu and Raspberry Pi OS)
and macOS.

Note that on macOS, I am using MacPorts for dependencies.  Homebrew
will probably work, I've just always been a MacPorts user.

## Dependencies
### Tools
#### C++ Compiler
A C++20 compiler is required.  I'm using these at the time of writing:
- FreeBSD: clang++ 18.1.4
- Ubuntu 24.04 LTS: g++ 13.2.0
- macOS: Apple clang version 15.0.0 (clang-1500.3.9.4)
- Raspberry Pi OS 12(bookworm): g++ 12.2.0
#### GNU make
- FreeBSD: `sudo pkg install gmake`
- Linux: `sudo apt install make`
#### GNU flex
- FreeBSD: `sudo pkg install flex`
- Linux: `sudo apt install flex`
#### GNU bison
- FreeBSD: `sudo pkg install bison`
- Linux: `sudo apt install bison`
- macOS: `sudo port install bison`
#### [mkfbsdmnfst](https://github.com/dwmcrobb/mkfbsdmnfst)
Needed to build a package on FreeBSD.
#### [mkdebcontrol](https://github.com/dwmcrobb/mkdebcontrol)
Needed to build a package on Debian, Ubuntu and Raspberry Pi OS.
### Libraries
#### [libDwm](https://github.com/dwmcrobb/libDwm)
#### libsodium
- FreeBSD: `sudo pkg install libsodium`
- Linux: `sudo apt install libsodium-dev`
- macOS: `sudo port install libsodium`
## Build
The build requires GNU make (hence on FreeBSD, the make command below
should be `gmake`).  It also requires GNU flex and GNU bison.

    ./configure
    make

## Build a native package
I normally build a native package to allow me to install the library
using the native packaging tools on FreeBSD, Debian-based Linux systems
and macOS.  This is done with:

    make package

Note that if you want documentation to be included in the build, you
must use:

    make BUILD_DOCS=yes package

## Installation
Once a package is built, it may be installed using the native installation
tools on your platform.
#### FreeBSD
    pkg install libDwmCredence-0.1.32.pkg
#### Linux (Debian-based systems)
    dpkg -i libDwmCredence_0.1.32_amd64.deb
#### macOS
    open libDwmCredence-0.1.32.pkg

#### Other options
You can stage all of the installation files without creating a package
by running:

    make tarprep
	
This will place all of the files for installation in the `staging/usr/local`
directory.  The top level `tarprep` make target is a dependency of the
`package` target.

## Documentation
Library documentation is available at
[www.mcplex.net/Software/Documentation/libDwmCredence](https://www.mcplex.net/Software/Documentation/libDwmCredence/)
and may be built in the `doc` directory.
