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

#include <chrono>

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
    Peer::Peer()
        : _keyExchangeTimeout(1000), _idExchangeTimeout(1000), _endPoint(),
          _theirId(), _agreedKey(), _ios(nullptr), _xis(nullptr),
          _xos(nullptr)
    { }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void Peer::SetKeyExchangeTimeout(std::chrono::milliseconds ms)
    {
      _keyExchangeTimeout = ms;
      return;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Peer::Accept(boost::asio::ip::tcp::socket && s)
    {
      using XChaCha20Poly1305::Istream, XChaCha20Poly1305::Ostream;
      
      bool  rc = false;
      _agreedKey.clear();
      _ios = make_unique<boost::asio::ip::tcp::iostream>(std::move(s));
      if (nullptr != _ios) {
        boost::system::error_code  ec;
        _endPoint = _ios->socket().remote_endpoint(ec);
        if (! ec) {
          if (KeyExchanger::ExchangeKeys(*_ios, _agreedKey,
                                         _keyExchangeTimeout)) {
            _xis = make_unique<Istream>(*_ios, _agreedKey);
            _xos = make_unique<Ostream>(*_ios, _agreedKey);
            rc = ((nullptr != _xis) && (nullptr != _xos));
          }
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Peer::Connect(const string & host, uint16_t port,
                       std::chrono::milliseconds timeOut)
    {
      using namespace boost::asio;
        
      bool  rc = false;
      _agreedKey.clear();
      if (nullptr == _ios) {
        _ios = make_unique<ip::tcp::iostream>();
        if (nullptr != _ios) {
          _ios->expires_from_now(timeOut);
          try {
            _ios->connect(host, to_string(port));
          }
          catch (...) {
            _ios = nullptr;
            return rc;
          }
          boost::system::error_code  ec;
          _endPoint = _ios->socket().remote_endpoint(ec);
          if (! ec) {
            if (KeyExchanger::ExchangeKeys(*_ios, _agreedKey,
                                           _keyExchangeTimeout)) {
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
    void Peer::SetIdExchangeTimeout(std::chrono::milliseconds ms)
    {
      _idExchangeTimeout = ms;
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
      if (_ios) {
        Authenticator  authenticator(keyStash, knownKeys);
        authenticator.SetIdExchangeTimeout(_idExchangeTimeout);
        if (authenticator.Authenticate(*_ios, _agreedKey, _theirId)) {
          rc = true;
        }
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
