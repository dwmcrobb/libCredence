//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//
//  1. Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//  3. The names of the authors and copyright holders may not be used to
//     endorse or promote products derived from this software without
//     specific prior written permission.
//
//  IN NO EVENT SHALL DANIEL W. MCROBB BE LIABLE TO ANY PARTY FOR
//  DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
//  INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE,
//  EVEN IF DANIEL W. MCROBB HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
//  DAMAGE.
//
//  THE SOFTWARE PROVIDED HEREIN IS ON AN "AS IS" BASIS, AND
//  DANIEL W. MCROBB HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT,
//  UPDATES, ENHANCEMENTS, OR MODIFICATIONS. DANIEL W. MCROBB MAKES NO
//  REPRESENTATIONS AND EXTENDS NO WARRANTIES OF ANY KIND, EITHER
//  IMPLIED OR EXPRESS, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE,
//  OR THAT THE USE OF THIS SOFTWARE WILL NOT INFRINGE ANY PATENT,
//  TRADEMARK OR OTHER RIGHTS.
//===========================================================================

//---------------------------------------------------------------------------
//!  \file TestPeer.cc
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#include <fstream>
#include <sstream>

#include "DwmIO.hh"
#include "DwmSysLogger.hh"
#include "DwmUnitAssert.hh"
#include "DwmCredencePeer.hh"

using namespace std;
using namespace Dwm;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
void ServerThread(const std::string & plaintext,
                  const std::atomic<bool> & shouldRun,
                  std::atomic<bool> & running)
{
  using namespace boost::asio;

  io_context                 ioContext;
  boost::system::error_code  ec;
  ip::tcp::endpoint  endPoint(ip::address::from_string("127.0.0.1"), 7789);
  ip::tcp::acceptor  acc(ioContext, endPoint);
  boost::asio::ip::tcp::acceptor::reuse_address option(true);
  acc.set_option(option, ec);
  acc.non_blocking(true, ec);

  ip::tcp::socket    sock(ioContext);
  ip::tcp::endpoint  client;
  running = true;
  while (shouldRun) {
    acc.accept(sock, client, ec);
    if (ec != boost::asio::error::would_block) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  if (! ec) {
    sock.native_non_blocking(false, ec);
    Credence::Peer       peer;
    if (UnitAssert(peer.Accept(std::move(sock)))) {
      Credence::KeyStash   keyStash("./inputs");
      Credence::KnownKeys  knownKeys("./inputs");
      if (UnitAssert(peer.Authenticate(keyStash, knownKeys))) {
        UnitAssert(peer.Id() == "test@mcplex.net");
        string  receivedtext;
        if (UnitAssert(peer.Receive(receivedtext))) {
          UnitAssert(plaintext == receivedtext);
        }
        UnitAssert(peer.Send(receivedtext));
      }
    }
  }
  running = false;
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
void ServerThread2(const std::string & plaintext,
                   const std::atomic<bool> & shouldRun,
                   std::atomic<bool> & running)
{
  using namespace boost::asio;

  io_context                 ioContext;
  boost::system::error_code  ec;
  ip::tcp::endpoint  endPoint(ip::address::from_string("127.0.0.1"), 7789);
  ip::tcp::acceptor  acc(ioContext, endPoint);
  boost::asio::ip::tcp::acceptor::reuse_address option(true);
  acc.set_option(option, ec);
  acc.non_blocking(true, ec);

  ip::tcp::socket    sock(ioContext);
  ip::tcp::endpoint  client;
  running = true;
  while (shouldRun) {
    acc.accept(sock, client, ec);
    if (ec != boost::asio::error::would_block) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  if (! ec) {
    sock.native_non_blocking(false, ec);
    Credence::Peer       peer;
    UnitAssert(peer.Accept(std::move(sock)));
  }
  running = false;
  return;
}

void TestServer()
{}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
bool GetFileContents(string & fileContents)
{
  bool  rc = false;
  ifstream  is("TestPeer.cc", ios::in | ios::binary);
  if (UnitAssert(is)) {
    is.seekg(0, ios::end);
    fileContents.resize(is.tellg());
    is.seekg(0, ios::beg);
    is.read(&fileContents[0], fileContents.size());
    is.close();
    rc = true;
  }
  return rc;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  using namespace boost::asio;

  // Dwm::SysLogger::Open("TestPeer", LOG_PID|LOG_PERROR, LOG_USER);
  
  std::atomic<bool>  serverShouldRun = true;
  std::atomic<bool>  serverIsRunning = false;
  
  string  fileContents;
  if (UnitAssert(GetFileContents(fileContents))) {
    std::thread  serverThread(ServerThread, fileContents,
                              std::ref(serverShouldRun),
                              std::ref(serverIsRunning));
    while (! serverIsRunning) { }
    Credence::Peer  peer;
    if (UnitAssert(peer.Connect("127.0.0.1", 7789))) {
      Credence::KeyStash   keyStash("./inputs");
      Credence::KnownKeys  knownKeys("./inputs");
      if (UnitAssert(peer.Authenticate(keyStash, knownKeys))) {
        if (UnitAssert(peer.Id() == "test@mcplex.net")) {
          if (UnitAssert(peer.Send(fileContents))) {
            string  recoveredContents;
            if (UnitAssert(peer.Receive(recoveredContents))) {
              UnitAssert(recoveredContents == fileContents);
            }
          }
        }
      }
      peer.Disconnect();
    }
    serverShouldRun = false;
    serverThread.join();

    serverShouldRun = true;
    serverIsRunning = false;
    std::thread  serverThread2(ServerThread2, fileContents,
                               std::ref(serverShouldRun),
                               std::ref(serverIsRunning));
    while (! serverIsRunning) { }
    if (UnitAssert(peer.Connect("127.0.0.1", 7789))) {
      peer.Disconnect();
      Credence::KeyStash   keyStash("./inputs");
      Credence::KnownKeys  knownKeys("./inputs");
      UnitAssert(! peer.Authenticate(keyStash, knownKeys));
    }
    serverShouldRun = false;
    serverThread2.join();
  }

  if (Assertions::Total().Failed()) {
    Assertions::Print(cerr, true);
    return 1;
  }
  else {
    cout << Assertions::Total() << " passed" << endl;
  }
  return 0;
}
