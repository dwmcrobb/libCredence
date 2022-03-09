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
//!  \file DwmCredenceServer.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Server class implementation
//---------------------------------------------------------------------------

#include "DwmIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceKXKeyPair.hh"
#include "DwmCredenceChallenge.hh"
#include "DwmCredenceChallengeResponse.hh"
#include "DwmCredenceServer.hh"
#include "DwmCredenceShortString.hh"
#include "DwmCredenceSigner.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Server::Server()
        : _endPoint(), _id(), _ios(), _sharedKey(), _xos(nullptr),
          _xis(nullptr)
    {}

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Server::~Server()
    {
      Disconnect();
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Server::Connect(const string & host, uint16_t port)
    {
      _ios.connect(host, std::to_string(port));
      if (_ios.socket().is_open()) {
        boost::system::error_code  ec;
        _ios.socket().native_non_blocking(false, ec);
        if (ExchangeKeys()) {
          _endPoint = _ios.socket().remote_endpoint();
          _xis = make_unique<XChaCha20Poly1305::Istream>(_ios, _sharedKey);
          _xos = make_unique<XChaCha20Poly1305::Ostream>(_ios, _sharedKey);
        }
        else {
          Syslog(LOG_ERR, "Key exchange failed");
          Disconnect();
        }
      }
      else {
        Syslog(LOG_ERR, "Failed to connect to %s:%hu", host.c_str(), port);
      }
      return (bool)_ios;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Server::Authenticate(const KeyStash & keyStash,
                              const KnownKeys & knownKeys)
    {
      bool  rc = false;
      Ed25519KeyPair  myKeys;
      string          serverPubKey;
      if (ExchangeIds(keyStash, knownKeys, myKeys, serverPubKey)) {
        if (ExchangeChallenges(myKeys.SecretKey(), serverPubKey)) {
          rc = true;
        }
        else {
          Syslog(LOG_ERR, "Challenge failed");
        }
      }
      else {
        Syslog(LOG_ERR, "ID exchange failed");
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const string & Server::Id() const
    {
      return _id;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Server::Send(const std::string & msg)
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
    bool Server::Send(const StreamWritable & msg)
    {
      bool  rc = false;
      if (_xos) {
        if (msg.Write(*_xos)) {
          if (_xos->flush()) {
            rc = true;
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
    bool Server::Receive(std::string & msg)
    {
      bool  rc = false;
      if (_xis) {
        if (IO::Read(*_xis, msg)) {
          rc = true;
        }
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Server::Receive(StreamReadable & msg)
    {
      bool  rc = false;
      if (_xis) {
        if (msg.Read(*_xis)) {
          rc = true;
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void Server::Disconnect()
    {
      if (_xis) {  _xis = nullptr;  }
      if (_xos) {  _xos = nullptr;  }
      if (_ios.socket().is_open()) {
        _ios.close();
        Syslog(LOG_INFO, "Disconnected server %s at %s",
               _id.c_str(), EndPointString().c_str());
      }
      _sharedKey.clear();
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Server::ExchangeKeys()
    {
      bool  rc = false;
      KXKeyPair  myKeys;
      if (IO::Write(_ios, myKeys.PublicKey())) {
        _ios.flush();
        string  serverPubKey;
        if (IO::Read(_ios, serverPubKey)) {
          _sharedKey = myKeys.ClientSharedKey(serverPubKey);
          rc = true;
        }
        else {
          Syslog(LOG_ERR, "Failed to read public key from server at %s",
                 EndPointString().c_str());
        }
      }
      else {
        Syslog(LOG_ERR, "Failed to send public key to server at %s",
               EndPointString().c_str());
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Server::ExchangeIds(const KeyStash & keyStash,
                             const KnownKeys & knownKeys,
                             Ed25519KeyPair & myKeys,
                             string & serverPubKey)
    {
      bool  rc = false;
      if (keyStash.Get(myKeys)) {
        ShortString  idShort(myKeys.Id());
        if (Send(idShort)) {
          if (Receive(_id)) {
            serverPubKey = knownKeys.Find(_id);
            rc = (! serverPubKey.empty());
            if (! rc) {
              Syslog(LOG_ERR, "Unknown ID %s from server at %s",
                     _id.c_str(), EndPointString().c_str());
            }
          }
          else {
            Syslog(LOG_ERR, "Failed to read ID from server at %s",
                   EndPointString().c_str());
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to send ID to server at %s",
                 EndPointString().c_str());
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Server::ExchangeChallenges(const std::string & mySecretKey,
                                    const std::string & serverPubKey)
    {
      bool  rc = false;
      //  Send challenge to server
      Challenge  serverChallenge(true);
      if (Send(serverChallenge)) {
        //  Receive challenge from server
        Challenge  myChallenge;
        if (Receive(myChallenge)) {
          //  Send my response
          ChallengeResponse  myResponse;
          if (myResponse.Create(mySecretKey, myChallenge)) {
            if (Send(myResponse)) {
              // Receive response from server
              ChallengeResponse  serverResponse;
              if (Receive(serverResponse)) {
                if (serverResponse.Verify(serverPubKey, serverChallenge)) {
                  rc = true;
                  Syslog(LOG_INFO, "Authenticated server %s at %s",
                         _id.c_str(), EndPointString().c_str());
                }
                else {
                  Syslog(LOG_INFO, "Failed to authenticate server %s at %s",
                         _id.c_str(), EndPointString().c_str());
                }
              }
              else {
                Syslog(LOG_ERR, "Failed to read server challenge response"
                       " from server %s at %s",
                       _id.c_str(), EndPointString().c_str());
              }
            }
            else {
              Syslog(LOG_ERR, "Failed to send challenge response to server"
                     " %s at %s",
                     _id.c_str(), EndPointString().c_str());
            }
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to read challenge from server %s at %s",
                 _id.c_str(), EndPointString().c_str());
        }
      }
      else {
        Syslog(LOG_ERR, "Failed to send challenge to server %s at %s",
               _id.c_str(), EndPointString().c_str());
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::string Server::EndPointString() const
    {
      return Utils::EndPointString(_endPoint);
    }

  }  // namespace Credence

}  // namespace Dwm

