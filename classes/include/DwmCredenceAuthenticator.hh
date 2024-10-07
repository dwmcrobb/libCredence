//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022, 2023
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
//!  \file DwmCredenceAuthenticator.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Authenticator class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEAUTHENTICATOR_HH_
#define _DWMCREDENCEAUTHENTICATOR_HH_

#include <chrono>
#include <boost/asio.hpp>

#include "DwmStreamIOCapable.hh"
#include "DwmCredenceKeyStash.hh"
#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceXChaCha20Poly1305Istream.hh"
#include "DwmCredenceXChaCha20Poly1305Ostream.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Used by Dwm::Credence::Peer for authentication.
    //------------------------------------------------------------------------
    class Authenticator
    {
    public:
      //----------------------------------------------------------------------
      //!  Construct from the given @c keyStash and @c knownKeys.
      //----------------------------------------------------------------------
      Authenticator(const KeyStash & keyStash, const KnownKeys & knownKeys);

      //----------------------------------------------------------------------
      //!  Sets the timeout for ID exchange to occur, in milliseconds.
      //----------------------------------------------------------------------
      void SetIdExchangeTimeout(std::chrono::milliseconds ms);
      
      //----------------------------------------------------------------------
      //!  Authenticate the peer connected to @c s using the previously
      //!  negotiated encryption key @c agreedKey to encrypt and decrypt all
      //!  communication.  For success, the peer's public key must be in our
      //!  KnownKeys and the peer must be able to properly sign a random
      //!  challenge we transmit to them.  In addition, our public key must
      //!  be in the peer's KnownKeys and we must be able to properly sign a
      //!  random challenge received from the peer.
      //!  Returns true on success and sets @c theirId to the ID of the peer.
      //----------------------------------------------------------------------
      bool Authenticate(boost::asio::ip::tcp::iostream & s,
                        const std::string & agreedKey,
                        std::string & theirId);

      //----------------------------------------------------------------------
      //!  Authenticate the peer connected to @c s using the previously
      //!  negotiated encryption key @c agreedKey to encrypt and decrypt all
      //!  communication.  For success, the peer's public key must be in our
      //!  KnownKeys and the peer must be able to properly sign a random
      //!  challenge we transmit to them.  In addition, our public key must
      //!  be in the peer's KnownKeys and we must be able to properly sign a
      //!  random challenge received from the peer.
      //!  Returns true on success and sets @c theirId to the ID of the peer.
      //----------------------------------------------------------------------
      bool Authenticate(boost::asio::local::stream_protocol::iostream & s,
                        const std::string & agreedKey,
                        std::string & theirId);
      
    private:
      KeyStash                                        _keyStash;
      KnownKeys                                       _knownKeys;
      std::chrono::milliseconds                       _timeout;
      boost::asio::ip::tcp::endpoint                  _endPoint;
      boost::asio::local::stream_protocol::endpoint   _lendPoint;
      std::unique_ptr<XChaCha20Poly1305::Ostream>     _xos;
      std::unique_ptr<XChaCha20Poly1305::Istream>     _xis;

      bool ExchangeIds(boost::asio::ip::tcp::iostream & s,
                       Ed25519KeyPair & myKeys,
                       ShortString<255> & theirId,
                       std::string & theirPubKey);
      bool ExchangeIds(boost::asio::local::stream_protocol::iostream & s,
                       Ed25519KeyPair & myKeys, ShortString<255> & theirId,
                       std::string & theirPubKey);
      bool ExchangeChallenges(const std::string & ourSecretKey,
                              const std::string & theirId,
                              const std::string & theirPubKey);
      bool Send(const std::string & msg);
      bool Send(const HasStreamWrite auto & msg);
      bool Receive(std::string & msg);
      bool Receive(HasStreamRead auto & msg);
      std::string EndPointString() const;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEAUTHENTICATOR_HH_
