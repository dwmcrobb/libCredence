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
//!  \file DwmCredenceServer.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Server class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCESERVER_HH_
#define _DWMCREDENCESERVER_HH_

#include <boost/asio.hpp>

#include "DwmStreamIOCapable.hh"
#include "DwmCredenceKeyStash.hh"
#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceXChaCha20Poly1305Istream.hh"
#include "DwmCredenceXChaCha20Poly1305Ostream.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates a server from the perspective of a client.
    //!  Uses XChacha20Poly1305 for authenticated encryption (AE).
    //------------------------------------------------------------------------
    class Server
    {
    public:
      //----------------------------------------------------------------------
      //!  Default constructor
      //----------------------------------------------------------------------
      Server();

      //----------------------------------------------------------------------
      //!  Destructor
      //----------------------------------------------------------------------
      ~Server();
      
      //----------------------------------------------------------------------
      //!  Connects to the given @c host at @c port, exchanges randomly
      //!  generated public keys and creates a shared encryption key.
      //!  Returns true on success, false on failure.
      //----------------------------------------------------------------------
      bool Connect(const std::string & host, uint16_t port);

      //----------------------------------------------------------------------
      //!  Authenticates the server and provides authentication to the
      //!  server.  Returns true on success, false on failure.  If used,
      //!  this should be called immediately after Connect() succeeds.
      //!  The KeyStash is used to authenticate ourselves to the server,
      //!  and the KnownKeys is used to authenticate the server to us.
      //----------------------------------------------------------------------
      bool Authenticate(const KeyStash & keyStash,
                        const KnownKeys & knownKeys);
      
      //----------------------------------------------------------------------
      //!  Returns the ID of the server.  The ID is used to find a public key
      //!  in the KnownKeys in Authenticate().  It is only valid if
      //!  authentication was successful.
      //----------------------------------------------------------------------
      const std::string & Id() const;
      
      //----------------------------------------------------------------------
      //!  Send the given @c msg to the server.  Returns true on success,
      //!  false on failure.
      //----------------------------------------------------------------------
      bool Send(const std::string & msg);
      
      //----------------------------------------------------------------------
      //!  Send the given @c msg to the server.  Returns true on success,
      //!  false on failure.
      //----------------------------------------------------------------------
      bool Send(const StreamWritable & msg);
      
      //----------------------------------------------------------------------
      //!  Receives @c msg from the server.  Returns true on success,
      //!  false on failure.
      //----------------------------------------------------------------------
      bool Receive(std::string & msg);
      
      //----------------------------------------------------------------------
      //!  Receives @c msg from the server.  Returns true on success,
      //!  false on failure.
      //----------------------------------------------------------------------
      bool Receive(StreamReadable & msg);
      
      //----------------------------------------------------------------------
      //!  Disconnects from the server.
      //----------------------------------------------------------------------
      void Disconnect();
      
    private:
      boost::asio::ip::tcp::endpoint               _endPoint;
      std::string                                  _id;
      boost::asio::ip::tcp::iostream               _ios;
      std::string                                  _sharedKey;
      std::unique_ptr<XChaCha20Poly1305::Ostream>  _xos;
      std::unique_ptr<XChaCha20Poly1305::Istream>  _xis;
      
      bool ExchangeKeys();
      bool ExchangeIds(const KeyStash & keyStash, const KnownKeys & knownKeys,
                       Ed25519KeyPair & myKeys, std::string & serverPubKey);
      bool ExchangeChallenges(const std::string & mySecretKey,
                              const std::string & serverPubKey);
      std::string EndPointString() const;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCESERVER_HH_
