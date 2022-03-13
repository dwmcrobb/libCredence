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
//!  \file TestXChaCha20Streams.cc
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#include <fstream>
#include <sstream>

#include "DwmIO.hh"
#include "DwmSysLogger.hh"
#include "DwmUnitAssert.hh"
#include "DwmCredenceKXKeyPair.hh"
#include "DwmCredenceServer.hh"
#include "DwmCredenceClient.hh"

using namespace std;
using namespace Dwm;

static std::atomic<bool>  g_serverStarted = false;
static std::atomic<bool>  g_serverShouldRun = true;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
void ServerThread(const std::string & plaintext)
{
  using namespace  boost::asio;
    io_context  ioContext;
  boost::system::error_code  ec;
  ip::tcp::endpoint  endPoint(ip::address::from_string("127.0.0.1"), 7789);
  ip::tcp::acceptor  acc(ioContext, endPoint);
  boost::asio::ip::tcp::acceptor::reuse_address option(true);
  acc.set_option(option, ec);
  acc.non_blocking(true, ec);

  ip::tcp::socket    socket(ioContext);
  ip::tcp::endpoint  client;
  ip::tcp::iostream  stream;
  g_serverStarted = true;
  while (g_serverShouldRun) {
    acc.accept(socket, client, ec);
    if (ec != boost::asio::error::would_block) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  if (! ec) {
    socket.native_non_blocking(false, ec);
    Credence::Client  client(std::move(socket));
    if (UnitAssert(client.ExchangeKeys())) {
      Credence::KeyStash  keyStash("./inputs");
      Credence::KnownKeys  knownKeys("./inputs");
      
      if (UnitAssert(client.Authenticate(keyStash, knownKeys))) {
        UnitAssert(client.Id() == "test@mcplex.net");
        string  receivedtext;
        if (UnitAssert(client.Receive(receivedtext))) {
          UnitAssert(plaintext == receivedtext);
        }
        UnitAssert(client.Send(receivedtext));
      }
    }
    client.Disconnect();
  }
  g_serverStarted = false;
  
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
void FuzzServerThread(const std::atomic<bool> & shouldRun,
                      std::atomic<bool> & running)
{
  using namespace  boost::asio;
    io_context  ioContext;
  boost::system::error_code  ec;
  ip::tcp::endpoint  endPoint(ip::address::from_string("127.0.0.1"), 7789);
  ip::tcp::acceptor  acc(ioContext, endPoint);
  boost::asio::ip::tcp::acceptor::reuse_address option(true);
  acc.set_option(option, ec);
  acc.non_blocking(true, ec);

  ip::tcp::endpoint  client;
  running = true;
  while (shouldRun) {
    ip::tcp::socket    socket(ioContext);
    acc.accept(socket, client, ec);
    if (ec == boost::asio::error::would_block) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    else {
      socket.native_non_blocking(false, ec);
      Credence::Client  client(std::move(socket));
      if (UnitAssert(client.ExchangeKeys())) {
        Credence::KeyStash   keyStash("./inputs");
        Credence::KnownKeys  knownKeys("./inputs");
        UnitAssert(! client.Authenticate(keyStash, knownKeys));
        client.Disconnect();
      }
    }
  }
  running = false;
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void FuzzTest1()
{
  
  atomic<bool>  serverShouldRun = true, serverIsRunning = false;
  std::thread  serverThread(FuzzServerThread, std::ref(serverShouldRun),
                            std::ref(serverIsRunning));
  while (! serverIsRunning) { }
  Credence::Server  server;
  if (UnitAssert(server.Connect("127.0.0.1", 7789))) {
    string  randomString(32, '\0');
    randombytes_buf((void *)randomString.data(), 32);
    randomString[0] = 0x1F;
    uint64_t  sendCount = 0;
    while (server.Send(randomString)) {
      randombytes_buf((void *)randomString.data(), 32);
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      ++sendCount;
    }
    UnitAssert(1 == sendCount);
    server.Disconnect();
  }
  
  serverShouldRun = false;
  serverThread.join();

  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  int  optChar;
  while ((optChar = getopt(argc, argv, "d")) != -1) {
    switch (optChar) {
      case 'd':
        Dwm::SysLogger::Open("TestClientServer", LOG_PID|LOG_PERROR, LOG_USER);
        Dwm::SysLogger::MinimumPriority(LOG_WARNING);
        break;
      default:
        break;
    }
  }
  
  for (int i = 0; i < 5; ++i) {
    FuzzTest1();
  }
  
  std::string    fileContents;
  std::ifstream  is("TestClientServer.cc", std::ios::in | std::ios::binary);
  if (UnitAssert(is)) {
    is.seekg(0, std::ios::end);
    fileContents.resize(is.tellg());
    is.seekg(0, std::ios::beg);
    is.read(&fileContents[0], fileContents.size());
    is.close();
  }

  g_serverStarted = false;
  g_serverShouldRun = true;
  
  std::thread  serverThread(ServerThread, fileContents);
  while (! g_serverStarted) { }

  Credence::Server  server;
  if (UnitAssert(server.Connect("127.0.0.1", 7789))) {
    Credence::KeyStash   keyStash("./inputs");
    Credence::KnownKeys  knownKeys("./inputs");
    if (UnitAssert(server.Authenticate(keyStash, knownKeys))) {
      UnitAssert(server.Id().Value() == "test@mcplex.net");
      if (UnitAssert(server.Send(fileContents))) {
        string  recoveredContents;
        if (UnitAssert(server.Receive(recoveredContents))) {
          UnitAssert(recoveredContents == fileContents);
        }
      }
    }
    server.Disconnect();
  }
  g_serverShouldRun = false;
  serverThread.join();
  
  if (Assertions::Total().Failed()) {
    Assertions::Print(cerr, true);
    return 1;
  }
  else {
    cout << Assertions::Total() << " passed" << endl;
  }
  return 0;
  
}
