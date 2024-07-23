#include "DwmCredencePeer.hh"

using namespace std;
using namespace boost::asio;
using namespace Dwm;

//----------------------------------------------------------------------------
static ip::tcp::socket AcceptSocket(io_context & ioContext,
                                    const string & addr, uint16_t port)
{
  ip::tcp::endpoint  endPoint(ip::address::from_string(addr), port);
  ip::tcp::acceptor  acc(ioContext, endPoint);
  boost::asio::ip::tcp::acceptor::reuse_address  option(true);
  acc.set_option(option);
  acc.non_blocking(false);

  ip::tcp::endpoint  client;
  ip::tcp::socket    sock(ioContext);
  acc.accept(sock, client);
  sock.native_non_blocking(false);
  return sock;
}

//----------------------------------------------------------------------------
static bool AcceptPeer(io_context & ioContext, const string & addr,
                       const string & port, Credence::Peer & peer)
{
  bool  rc = false;
  try {
    ip::tcp::socket  sock = AcceptSocket(ioContext, addr, std::stoul(port));
    if (sock.is_open()) {
      rc = peer.Accept(std::move(sock));
    }
  }
  catch (std::exception & ex) {
    cerr << "Exception: " << ex.what() << '\n';
  }
  return rc;
}

//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  if (argc < 3) {
    cerr << "Usage: " << argv[0] << " addr port\n";
    return 1;
  }

  int  rc = 1;
  io_context      ioContext;
  Credence::Peer  peer;
  if (AcceptPeer(ioContext, argv[1], argv[2], peer)) {
    Credence::KeyStash   keyStash;
    Credence::KnownKeys  knownKeys;
    if (peer.Authenticate(keyStash, knownKeys)) {
      rc = 0;
      string  msg;
      do {
        if (! peer.Receive(msg)) { rc = 1; break; }
        if (! peer.Send(msg))    { rc = 1; break; }
      } while (msg != "Goodbye");
    }
    else {
      cerr << "Authentication failed\n";
    }
  }
  else {
    cerr << "AcceptPeer failed\n";
  }
  
  return rc;
}
