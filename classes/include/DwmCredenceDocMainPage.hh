/*! @file DwmCredenceDocMainPage.hh
 *  @brief Documentation main page (no source code)
 * 
 * \mainpage DwmCredence Class Library
 *
 *  \section intro_sec Introduction
 *
 *  This class library may be used for secure, authenticated network
 *  communication over TCP.  The main three classes are Dwm::Credence::Peer,
 *  Dwm::Credence::KeyStash and Dwm::Credence::KnownKeys.  Utilizing just
 *  these three classes, it is relatively easy to create secure TCP
 *  applications.
 *
 *  The library depends on <A HREF="https://doc.libsodium.org/">libsodium</A>,
 *  <A HREF="https://www.boost.org/doc/libs/1_79_0/doc/html/boost_asio.html">
 *  boost::asio</A> and <A HREF="..\libDwm">libDwm</A>.
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
 *  This library came about when I needed a replacement for Crypto++
 *  (needed by libDwmAuth).  In my own applications, libDwmAuth will
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
 *  \section examples Examples
 *
 *  \subsection example_assumptions Assumptions
 *
 *  The examples assume that you have created your key files by running
 *  <code>credence keygen</code>, and that they are present in the default
 *  directory (<code>~/.credence</code>).  They also assume that you have
 *  your own public key (from <code>~/.credence/id_ed25519.pub</code>)
 *  in the default <code>~/.credence/known_keys</code> file.
 *
 *  \subsection echo_example Simple echo
 *
 *  \subsubsection echo_client_example Simple echo client
 *
 *  \includelineno PeerClientExample1.cc
 *
 *  \subsubsection echo_server_example Simple echo server
 *
 *  Note that this server only accepts one client, and will exit after
 *  communicating with the client.  In other words, it's not typical, but
 *  instead is a minimal illustration.
 *
 *  \includelineno PeerServerExample1.cc
 *
 */
