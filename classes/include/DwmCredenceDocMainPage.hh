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
 *  \section main_abstractions_sec Main Library Abstractions
 *  \subsection peer_subsec Peer
 *  The @ref Dwm::Credence::Peer "Peer" class encapsulates a connection,
 *  via TCP or a UNIX domain socket.  It is the main interface through
 *  which connections are initiated (via the
 *  @ref Dwm::Credence::Peer::Connect() "Connect()" member),
 *  accepted (via the @ref Dwm::Credence::Peer::Accept() "Accept()" member),
 *  and authenticated (via the @ref Dwm::Credence::Peer::Authenticate
 *  "Authenticate()" member).  It is also the interface through which
 *  messages are sent (via the @ref Dwm::Credence::Peer::Send() "Send()"
 *  member) and received (via the @ref Dwm::Credence::Peer::Receive()
 *  "Receive()" member).
 *  \subsubsection peer_connect_subsubsec Connection Establishment
 *  A client utilizes the @ref Dwm::Credence::Peer::Connect() "Connect()"
 *  member to connect to a server.  A server accepts incoming connections
 *  via the @ref Dwm::Credence::Peer::Accept() "Accept()" member.  As part
 *  of the connection setup, a shared encryption key is derived by each
 *  side.  This key is ephemeral (only used for this connection), and
 *  used to encrypt all future traffic between the peers.
 *  
 *  \subsubsection authentication_subsubsec Mutual Authentication
 *  The @ref Dwm::Credence::Peer::Authenticate "Authenticate()" member of
 *  the @ref Dwm::Credence::Peer "Peer" class performs mutual authentication.
 *  It verifies the claimed identity of the remote service and provides
 *  verifiable evidence of the identity of the local application to the
 *  remote service.  It returns true if authentication succeeds, false if
 *  it fails.
 *  \subsubsection send_receive_subsec Send and Receive Messages
 *  Messages are exchanged using the @ref Dwm::Credence::Peer::Send()
 *  "Send()" and @ref Dwm::Credence::Peer::Receive() "Receive()" members
 *  of the @ref Dwm::Credence::Peer "Peer" class.  These are member
 *  function templates, and use @c Dwm::StreamIO functionality from libDwm
 *  to allow sending and receiving all types supported directly by libDwm
 *  as well as all types which implement the requirements of the
 *  Dwm::HasStreamRead and Dwm::HasStreamWrite concepts.
 *  \subsection key_stash_known_keys_subsec Key Stash and Known Keys
 *  \subsubsection key_stash_subsubsec Key Stash
 *  \subsubsection known_keys_subsubsec Known Keys
 *
 *  \section history_sec History
 *
 *  This library came about when I needed a replacement for Crypto++
 *  (needed by libDwmAuth).  In my own applications, libDwmAuth was
 *  replaced by libDwmCredence.  The new name is a hint that it's
 *  not the same as libDwmAuth under the hood, and allowed me to migrate
 *  my applications as I had time.
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
