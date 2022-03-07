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
//!  \file DwmCredenceClient.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Client class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCECLIENT_HH_
#define _DWMCREDENCECLIENT_HH_

#include <boost/asio.hpp>

#include "DwmStreamIOCapable.hh"
#include "DwmCredenceKeyStash.hh"
#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceXChaCha20Poly1305Istream.hh"
#include "DwmCredenceXChaCha20Poly1305Ostream.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates a client from the perspective of a server.  Uses
    //!  XChaCha20Poly1305 for authenticated encryption.
    //------------------------------------------------------------------------
    class Client
    {
    public:
      //----------------------------------------------------------------------
      //!  Construct from the given socket @c s.
      //----------------------------------------------------------------------
      Client(boost::asio::ip::tcp::socket && s);

      //----------------------------------------------------------------------
      //!  Exchanges public keys.  On success, creates a shared encryption
      //!  key and encrypted stream and returns true.  On failure, returns
      //!  false.  This must be called immediately after the constructor.
      //----------------------------------------------------------------------
      bool ExchangeKeys();

      //----------------------------------------------------------------------
      //!  Authenticates ourselves to the client using the given @c keyStash
      //!  and the client to us using the given @c knownKeys.  Returns true
      //!  on success, false on failure.  This should be called immediately
      //!  after ExchangeKeys() if authentication is desired.
      //----------------------------------------------------------------------
      bool Authenticate(const KeyStash & keyStash,
                        const KnownKeys & knownKeys);

      //----------------------------------------------------------------------
      //!  Returns the ID that was presented by the client during
      //!  authentication.  Only valid if authentication was successful.
      //----------------------------------------------------------------------
      const std::string & Id() const;

      //----------------------------------------------------------------------
      //!  Sends the given @c msg to the client.  Returns true on success,
      //!  false on failure.
      //----------------------------------------------------------------------
      bool Send(const std::string & msg);

      //----------------------------------------------------------------------
      //!  Sends the given @c msg to the client.  Returns true on success,
      //!  false on failure.
      //----------------------------------------------------------------------
      bool Send(const StreamWritable & msg);

      //----------------------------------------------------------------------
      //!  Receives @c msg from the client.  Returns true on success, false
      //!  on failure.
      //----------------------------------------------------------------------
      bool Receive(std::string & msg);

      //----------------------------------------------------------------------
      //!  Receives @c msg from the client.  Returns true on success, false
      //!  on failure.
      //----------------------------------------------------------------------
      bool Receive(StreamReadable & msg);

      //----------------------------------------------------------------------
      //!  Disconnects the client.
      //----------------------------------------------------------------------
      void Disconnect();
      
    private:
      boost::asio::ip::tcp::iostream               _ios;
      boost::asio::ip::tcp::endpoint               _endPoint;
      std::string                                  _id;
      std::string                                  _sharedKey;
      std::unique_ptr<XChaCha20Poly1305::Ostream>  _xos;
      std::unique_ptr<XChaCha20Poly1305::Istream>  _xis;
      
      bool ExchangeIds(const KeyStash & keyStash, const KnownKeys & knownKeys,
                       Ed25519KeyPair & myKeys, std::string & clientPubKey);
      bool ExchangeChallenges(const std::string & mySecretKey,
                              const std::string & clientPubKey);
      
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCECLIENT_HH_
