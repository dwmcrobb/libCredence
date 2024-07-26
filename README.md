# Dwm::Credence C++ Class Library
This class library may be used for secure, authenticated network
communication over TCP.  The main three classes are 
[Dwm::Credence::Peer](https://www.mcplex.net/Software/Documentation/libDwmCredence/classDwm_1_1Credence_1_1Peer.html),
[Dwm::Credence::KeyStash](https://www.mcplex.net/Software/Documentation/libDwmCredence/classDwm_1_1Credence_1_1KeyStash.html)
and 
[Dwm::Credence::KnownKeys](https://www.mcplex.net/Software/Documentation/libDwmCredence/classDwm_1_1Credence_1_1KnownKeys.html).
Utilizing just these three classes, it is relatively easy to create secure TCP
applications.  There is an example in the [library documentation](https://www.mcplex.net/Software/Documentation/libDwmCredence/).

Since I wanted something I could use across a variety of C++ client/server
applications, I needed something that made it easy to send and receive
objects of a wide range of abstract data types.  The easiest way to do this
was to utilize the 
[Dwm::StreamIO](https://www.mcplex.net/Software/Documentation/libDwm/classDwm_1_1StreamIO.html)
abstractions from [libDwm](https://github.com/dwmcrobb/libDwm), which only
requires that my messages are composed from fundamental types, objects which
implement the
[Dwm::HasStreamRead](https://www.mcplex.net/Software/Documentation/libDwm/conceptDwm_1_1HasStreamRead.html)
and [Dwm::HasStreamWrite](https://www.mcplex.net/Software/Documentation/libDwm/conceptDwm_1_1HasStreamWrite.html) concepts, and
containers of either or both.  To be able to send and recieve the contents
of a given class, I only need to implement Read(istream &) and Write(ostream &)
members, and those are typically easy to do given the facilities in
[Dwm::StreamIO](https://www.mcplex.net/Software/Documentation/libDwm/classDwm_1_1StreamIO.html).
As a result, I have more than half a dozen client/server application systems
that utilize the library.

## History
This library replaced my older Dwm::Auth library that used Crypto++
under the hood.  I had some problems with Crypto++ that went
unresolved after reporting them, which forced me to maintain
my own private fork with my fixes and start designing a new library
around something else.  That something else being 
[libsodium](https://doc.libsodium.org), which is much smaller, and a
good fit for my needs.  It has its frailties (C arrays and pointers
that require care), but it's well-maintained, proven, widely used and
has good documentation.

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
