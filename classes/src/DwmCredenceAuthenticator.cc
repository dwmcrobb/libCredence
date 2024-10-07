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
//!  \file DwmCredenceAuthenticator.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Authenticator class implementation
//---------------------------------------------------------------------------

#include "DwmIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceAuthenticator.hh"
#include "DwmCredenceChallengeResponse.hh"
#include "DwmCredenceKXKeyPair.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    Authenticator::Authenticator(const KeyStash & keyStash,
                                 const KnownKeys & knownKeys)
        : _keyStash(keyStash), _knownKeys(knownKeys)
    {}

    //------------------------------------------------------------------------
    bool Authenticator::Authenticate(boost::asio::ip::tcp::iostream & s,
                                     const std::string & agreedKey,
                                     string & theirId)
    {
      bool  rc = false;
      theirId.clear();
      if (s.socket().is_open()) {
        boost::system::error_code  ec;
        _endPoint = s.socket().remote_endpoint(ec);
        if (! ec) {
          _xis = make_unique<XChaCha20Poly1305::Istream>(s, agreedKey);
          _xos = make_unique<XChaCha20Poly1305::Ostream>(s, agreedKey);
          if ((nullptr != _xis) && (nullptr != _xos)) {
            Ed25519KeyPair    myKeys;
            Ed25519PublicKey  theirPubKey;
            if (ExchangeIds(s, myKeys, theirPubKey)) {
              if (ExchangeChallenges(myKeys.SecretKey(), theirPubKey)) {
                theirId = theirPubKey.Id();
                rc = true;
              }
            }
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to get remote_endpoint");
        }
      }
      
      return rc;
    }

    //------------------------------------------------------------------------
    bool Authenticator::
    Authenticate(boost::asio::local::stream_protocol::iostream & s,
                 const std::string & agreedKey, string & theirId)
    {
      bool  rc = false;
      theirId.clear();
      if (s.socket().is_open()) {
        boost::system::error_code  ec;
        _lendPoint = s.socket().remote_endpoint(ec);
        if (! ec) {
          _xis = make_unique<XChaCha20Poly1305::Istream>(s, agreedKey);
          _xos = make_unique<XChaCha20Poly1305::Ostream>(s, agreedKey);
          if ((nullptr != _xis) && (nullptr != _xos)) {
            Ed25519KeyPair    myKeys;
            Ed25519PublicKey  theirPubKey;
            if (ExchangeIds(s, myKeys, theirPubKey)) {
              if (ExchangeChallenges(myKeys.SecretKey(), theirPubKey)) {
                theirId = theirPubKey.Id();
                rc = true;
              }
            }
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to get remote_endpoint");
        }
      }
      
      return rc;
    }
    
    //------------------------------------------------------------------------
    void Authenticator::SetIdExchangeTimeout(std::chrono::milliseconds ms)
    {
      _timeout = ms;
      return;
    }

    //------------------------------------------------------------------------
    bool Authenticator::ExchangeIds(boost::asio::ip::tcp::iostream & s,
                                    Ed25519KeyPair & myKeys,
                                    Ed25519PublicKey & theirPubKey)
    {
      bool  rc = false;
      if (_keyStash.Get(myKeys)) {
        ShortString<255>  myId(myKeys.PublicKey().Id());
        if (Send(myId)) {
          uint32_t  minBytes = crypto_secretbox_NONCEBYTES
            + crypto_aead_xchacha20poly1305_ietf_ABYTES + 1;
          if (Utils::WaitForBytesReady(s.socket(), minBytes, _timeout)) {
            ShortString<255> theirId;
            string           theirPubKeyStr;
            if (Receive(theirId)) {
              theirPubKeyStr = _knownKeys.Find(theirId.Value());
              if (! theirPubKeyStr.empty()) {
                theirPubKey =
                  Ed25519PublicKey(theirId.Value(), theirPubKeyStr);
                rc = true;
              }
              else {
                FSyslog(LOG_ERR, "Unknown ID {} from peer at {}",
                        theirId.Value(), EndPointString());
              }
            }
            else {
              FSyslog(LOG_ERR, "Failed to read ID from peer at {}",
                      EndPointString());
            }
          }
          else {
            FSyslog(LOG_ERR, "Peer at {} failed to send ID within {}"
                    " milliseconds", EndPointString(), _timeout.count());
          }
        }
        else {
          FSyslog(LOG_ERR, "Failed to send ID to peer at {}",
                  EndPointString());
        }
      }
      else {
        FSyslog(LOG_ERR, "Failed to get my keys from KeyStash in '{}'",
                _keyStash.DirName());
      }
      return rc;
    }

    //------------------------------------------------------------------------
    bool Authenticator::
    ExchangeIds(boost::asio::local::stream_protocol::iostream & s,
                Ed25519KeyPair & myKeys, Ed25519PublicKey & theirPubKey)
    {
      bool  rc = false;
      if (_keyStash.Get(myKeys)) {
        ShortString<255>  myId(myKeys.PublicKey().Id());
        if (Send(myId)) {
          uint32_t  minBytes = crypto_secretbox_NONCEBYTES
            + crypto_aead_xchacha20poly1305_ietf_ABYTES + 1;
          if (Utils::WaitForBytesReady(s.socket(), minBytes, _timeout)) {
            ShortString<255> theirId;
            string           theirPubKeyStr;                                   
            if (Receive(theirId)) {
              theirPubKeyStr = _knownKeys.Find(theirId.Value());
              if (! theirPubKeyStr.empty()) {
                theirPubKey =
                  Ed25519PublicKey(theirId.Value(), theirPubKeyStr);
                rc = true;
              }
              else {
                FSyslog(LOG_ERR, "Unknown ID {} from peer at {}",
                        theirId.Value(), EndPointString());
              }
            }
            else {
              FSyslog(LOG_ERR, "Failed to read ID from peer at {}",
                      EndPointString());
            }
          }
          else {
            FSyslog(LOG_ERR, "Peer at {} failed to send ID within {}"
                    " milliseconds", EndPointString(), _timeout.count());
          }
        }
        else {
          FSyslog(LOG_ERR, "Failed to send ID to peer at {}",
                  EndPointString());
        }
      }
      else {
        FSyslog(LOG_ERR, "Failed to get my keys from KeyStash in '{}'",
                _keyStash.DirName());
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Authenticator::ExchangeChallenges(const string & ourSecretKey,
                                           const Ed25519PublicKey & theirPubKey)
    {
      bool  rc = false;
      //  Send our challenge
      Challenge  ourChallenge(true);
      if (Send(ourChallenge)) {
        //  Receive their challenge
        Challenge  theirChallenge;
        if (Receive(theirChallenge)) {
          //  Send our response
          ChallengeResponse  ourResponse;
          if (ourResponse.Create(ourSecretKey, theirChallenge)) {
            if (Send(ourResponse)) {
              //  Receive their response
              ChallengeResponse  theirResponse;
              if (Receive(theirResponse)) {
                if (theirResponse.Verify(theirPubKey, ourChallenge)) {
                  rc = true;
                  FSyslog(LOG_INFO, "Authenticated {} at {}",
                          theirPubKey.Id(), EndPointString());
                }
                else {
                  FSyslog(LOG_INFO, "Failed to authenticate {} at {}",
                          theirPubKey.Id(), EndPointString());
                }
              }
              else {
                FSyslog(LOG_ERR, "Failed to read challenge response from"
                        " {} at {}", theirPubKey.Id(), EndPointString());
              }
            }
            else {
              FSyslog(LOG_ERR, "Failed to send challenge response to"
                      " {} at {}", theirPubKey.Id(), EndPointString());
            }
          }
        }
        else {
          FSyslog(LOG_ERR, "Failed to read challenge from {} at {}",
                  theirPubKey.Id(), EndPointString());
        }
      }
      else {
        FSyslog(LOG_ERR, "Failed to send challenge to {} at {}",
                theirPubKey.Id(), EndPointString());
      }

      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Authenticator::Send(const string & msg)
    {
      bool  rc = false;
      if (_xos) {
        if (IO::Write(*_xos, msg)) {
          if (_xos->flush()) {
            rc = true;
          }
          else {
            Syslog(LOG_ERR, "Failed to flush _xos");
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to write msg to _xos");
        }
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Authenticator::Send(const HasStreamWrite auto & msg)
    {
      bool  rc = false;
      if (_xos) {
        if (msg.Write(*_xos)) {
          if (_xos->flush()) {
            rc = true;
          }
          else {
            Syslog(LOG_ERR, "Failed to flush _xos");
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to write msg to _xos");
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Authenticator::Receive(string & msg)
    {
      bool  rc = false;
      if (_xis) {
        if (IO::Read(*_xis, msg)) {
          rc = true;
        }
        else {
          Syslog(LOG_ERR, "Failed to read msg from _xis");
        }
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Authenticator::Receive(HasStreamRead auto & msg)
    {
      bool  rc = false;
      if (_xis) {
        if (msg.Read(*_xis)) {
          rc = true;
        }
        else {
          Syslog(LOG_ERR, "Failed to read msg from _xis");
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::string Authenticator::EndPointString() const
    {
      return Utils::EndPointString(_endPoint);
    }
    
  }  // namespace Credence

}  // namespace Dwm
