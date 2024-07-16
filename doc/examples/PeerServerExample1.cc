#include "DwmCredencePeer.hh"

using namespace std;
using namespace boost::asio;
using namespace Dwm;

//----------------------------------------------------------------------------
static bool AcceptPeer(io_context & ioContext, const string & addr,
                       const string & port, Credence::Peer & peer)
{
  bool                       rc = false;
  boost::system::error_code  ec;
  ip::tcp::endpoint          endPoint(ip::address::from_string(addr),
                                      std::stoul(port));
  ip::tcp::acceptor          acc(ioContext, endPoint);
  boost::asio::ip::tcp::acceptor::reuse_address option(true);
  acc.set_option(option, ec);
  if (! ec) {
    acc.non_blocking(false, ec);
    if (! ec) {
      ip::tcp::socket    sock(ioContext);
      ip::tcp::endpoint  client;
      acc.accept(sock, client, ec);
      if (! ec) {
        sock.native_non_blocking(false, ec);
        rc = peer.Accept(std::move(sock));
      }
      else { cerr << "accept() failed\n"; }
    }
    else { cerr << "Failed to set socket as blocking\n"; }
  }
  else { cerr << "Failed to set reuse_addr option\n"; }
  
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
