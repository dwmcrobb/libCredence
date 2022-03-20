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
//!  \file DwmCredencePeer.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Peer class implementation
//---------------------------------------------------------------------------

#include "DwmCredenceAuthenticator.hh"
#include "DwmCredenceKeyExchanger.hh"
#include "DwmCredencePeer.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Peer::Accept(boost::asio::ip::tcp::socket && s)
    {
      bool  rc = false;
      _agreedKey.clear();
      _ios = make_unique<boost::asio::ip::tcp::iostream>(std::move(s));
      if (nullptr != _ios) {
        boost::system::error_code  ec;
        _endPoint = _ios->socket().remote_endpoint(ec);
        if (! ec) {
          if (KeyExchanger::ExchangeKeys(*_ios, _agreedKey)) {
            _xis = make_unique<XChaCha20Poly1305::Istream>(*_ios, _agreedKey);
            _xos = make_unique<XChaCha20Poly1305::Ostream>(*_ios, _agreedKey);
            rc = ((nullptr != _xis) && (nullptr != _xos));
          }
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Peer::Connect(const string & host, uint16_t port)
    {
      using namespace boost::asio;
      
      bool  rc = false;
      _agreedKey.clear();
      if (nullptr == _ios) {
        _ios = make_unique<ip::tcp::iostream>(host, to_string(port));
        if (nullptr != _ios) {
          boost::system::error_code  ec;
          _endPoint = _ios->socket().remote_endpoint(ec);
          if (! ec) {
            if (KeyExchanger::ExchangeKeys(*_ios, _agreedKey)) {
              _xis = make_unique<XChaCha20Poly1305::Istream>(*_ios, _agreedKey);
              _xos = make_unique<XChaCha20Poly1305::Ostream>(*_ios, _agreedKey);
              rc = ((nullptr != _xis) && (nullptr != _xos));
            }
          }
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void Peer::Disconnect()
    {
      _xos = nullptr;
      _xis = nullptr;
      _ios = nullptr;
      _agreedKey.clear();
      return;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Peer::Authenticate(const KeyStash & keyStash,
                            const KnownKeys & knownKeys)
    {
      bool  rc = false;
      _theirId.clear();
      Authenticator  authenticator(keyStash, knownKeys);
      if (authenticator.Authenticate(*_ios, _agreedKey, _theirId)) {
        rc = true;
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::string Peer::EndPointString() const
    {
      return Utils::EndPointString(_endPoint);
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
