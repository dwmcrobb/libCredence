/*! @file DwmCredenceDocMainPage.hh
 *  @brief Documentation main page (no source code)
 * 
 * \mainpage DwmCredence Class Library
 *
 *  \section intro_sec Introduction
 *
 *  This class library may be used for secure, authenticated network
 *  communicator over TCP.  The main three classes are Peer, KeyStash
 *  and KnownKeys.  Utilizing just these three classes, it is relatively
 *  easy to create secure TCP applications.
 *
 *  The library depends on libsodium, boost::asio and libDwm.
 *
 *  Since I'm using libsodium, I'm using XChaCha20Poly1305 for
 *  encryption.  User and server authentication uses signatures
 *  produced and validated with Ed25519 keys.
 *
 *  No passwords are used, only key files (which aren't password
 *  protected).  This is intentional since my main usage is in applications
 *  that are not launched interactively.  I may later add password
 *  protected keys.
 *  
 *  \section history_sec History
 *
 *  This library came about when I grew tired of problems introduced
 *  in Crypto++ that forced me to maintain my own personal fork that
 *  was needed by libDwmAuth.  In my own applications, libDwmAuth will
 *  be replaced by libDwmCredence.  The new name is a hint that it's
 *  not the same as libDwmAuth under the hood, and allows me to migrate
 *  my applications as I have time.
 *
 *  \section platforms_sec Platforms
 *
 *  I only maintain support for 4 platforms: FreeBSD, macOS, desktop linux
 *  and Raspbian (now Raspberry Pi OS).  FreeBSD is my operating system of
 *  choice for servers and macOS is my operating system of choice for
 *  desktops and laptops.  I have several Raspberry Pis I utilize for
 *  various tasks, and Ubuntu VMs and Ubuntu workstations.
 *
 *  \tableofcontents
 *
*/
