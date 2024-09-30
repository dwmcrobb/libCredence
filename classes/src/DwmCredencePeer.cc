//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022, 2023, 2024
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
          _theirId(), _agreedKey(), _ios(nullptr), _lios(nullptr),
          _xis(nullptr), _xos(nullptr)
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
    bool Peer::Accept(boost::asio::local::stream_protocol::socket && s)
    {
      using XChaCha20Poly1305::Istream, XChaCha20Poly1305::Ostream;
      
      bool  rc = false;
      _agreedKey.clear();
      _lios = make_unique<boost::asio::local::stream_protocol::iostream>(std::move(s));
      if (nullptr != _lios) {
        boost::system::error_code  ec;
        _lendPoint = _lios->socket().remote_endpoint(ec);
        if (! ec) {
          if (KeyExchanger::ExchangeKeys(*_lios, _agreedKey,
                                         _keyExchangeTimeout)) {
            _xis = make_unique<Istream>(*_lios, _agreedKey);
            _xos = make_unique<Ostream>(*_lios, _agreedKey);
            rc = ((nullptr != _xis) && (nullptr != _xos));
          }
        }
      }
      return rc;
    }
    
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
          _ios->expires_after(timeOut);
          try {
            _ios->connect(host, to_string(port));
          }
          catch (...) {
            _ios = nullptr;
            return rc;
          }
          _ios->expires_after(std::chrono::milliseconds(60000));
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
    bool Peer::Connect(const string & path, std::chrono::milliseconds timeOut)
    {
      using namespace boost::asio;
        
      bool  rc = false;
      _agreedKey.clear();
      if (nullptr == _lios) {
        _lios = make_unique<local::stream_protocol::iostream>();
        if (nullptr != _lios) {
          _lios->expires_after(timeOut);
          try {
            _lios->connect(local::stream_protocol::endpoint(path.c_str()));
          }
          catch (...) {
            _lios = nullptr;
            return rc;
          }
          _lios->expires_after(std::chrono::milliseconds(60000));
          boost::system::error_code  ec;
          _lendPoint = _lios->socket().remote_endpoint(ec);
          if (! ec) {
            if (KeyExchanger::ExchangeKeys(*_lios, _agreedKey,
                                           _keyExchangeTimeout)) {
              _xis = make_unique<XChaCha20Poly1305::Istream>(*_lios, _agreedKey);
              _xos = make_unique<XChaCha20Poly1305::Ostream>(*_lios, _agreedKey);
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
      if (_ios) {
        _ios->close();
        _ios = nullptr;
      }
      if (_lios) {
        _lios->close();
        _lios = nullptr;
      }
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
      else if (_lios) {
        Authenticator  authenticator(keyStash, knownKeys);
        authenticator.SetIdExchangeTimeout(_idExchangeTimeout);
        if (authenticator.Authenticate(*_lios, _agreedKey, _theirId)) {
          rc = true;
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Peer::ReceiveWouldBlock(size_t numBytes)
    {
      if (_ios) {
        ssize_t  bytesReady = Utils::BytesReady(_ios->socket());
        if ((0 <= bytesReady) && (bytesReady < numBytes)) {
          return true;
        }
      }
      else if (_lios) {
        ssize_t  bytesReady = Utils::BytesReady(_lios->socket());
        if ((0 <= bytesReady) && (bytesReady < numBytes)) {
          return true;
        }
      }
      return false;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::string Peer::EndPointString() const
    {
      std::string  rc;
      if (_endPoint.data()) {
        rc = Utils::EndPointString(_endPoint);
      }
      else if (_lendPoint.data()) {
        rc = _lendPoint.path();
      }
      return rc;
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
