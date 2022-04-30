#include "DwmCredencePeer.hh"

int main(int argc, char *argv[])
{
  using namespace std;
  using namespace Dwm;
  
  int  rc = 1;
  
  if (argc < 3) {
    cerr << "Usage: " << argv[0] << " host port\n";
    return 1;
  }
  
  Credence::Peer  peer;
  if (peer.Connect(argv[1], std::stoul(argv[2]))) {
    Credence::KeyStash   keyStash;
    Credence::KnownKeys  knownKeys;
    if (peer.Authenticate(keyStash, knownKeys)) {
      rc = 0;
      string  msg;
      while (std::getline(cin, msg)) {
        if (! peer.Send(msg))    { rc = 1; break; }
        if (! peer.Receive(msg)) { rc = 1; break; }
        cout << msg << '\n';
        if (msg == "Goodbye")    { break; }
      }
    }
    else {
      cerr << "Failed to authenticate to " << argv[1]
           << " port " << argv[2] << '\n';
    }
  }
  else {
    cerr << "Failed to connect to " << argv[1]
         << " port " << argv[2] << '\n';
  }
  
  return rc;
}
