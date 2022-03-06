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
//!  \file DwmCredenceClient.cc
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#include "DwmIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceKXKeyPair.hh"
#include "DwmCredenceChallenge.hh"
#include "DwmCredenceChallengeResponse.hh"
#include "DwmCredenceClient.hh"
#include "DwmCredenceSigner.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Client::Client(boost::asio::ip::tcp::socket && s)
        : _ios(std::move(s)), _sharedKey()
    {}
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Client::Authenticate(const KeyStash & keyStash,
                              const KnownKeys & knownKeys)
    {
      bool  rc = false;
      if (ExchangeKeys()) {
        _xis = std::make_unique<XChaCha20Poly1305::Istream>(_ios, _sharedKey);
        _xos = std::make_unique<XChaCha20Poly1305::Ostream>(_ios, _sharedKey);
        Ed25519KeyPair  myKeys;
        string          clientPubKey;
        if (ExchangeIds(keyStash, knownKeys, myKeys, clientPubKey)) {
          if (ExchangeChallenges(myKeys.SecretKey(), clientPubKey)) {
            rc = true;
          }
        }
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Client::SendTo(const std::string & msg)
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
    bool Client::SendTo(const StreamWritable & msg)
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
    bool Client::ReceiveFrom(std::string & msg)
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
    bool Client::ReceiveFrom(StreamReadable & msg)
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
    bool Client::ExchangeKeys()
    {
      bool  rc = false;
      KXKeyPair  myKeys;
      if (IO::Write(_ios, myKeys.PublicKey())) {
        string  clientPubKey;
        if (IO::Read(_ios, clientPubKey)) {
          _sharedKey = myKeys.ServerSharedKey(clientPubKey);
          rc = true;
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Client::ExchangeIds(const KeyStash & keyStash,
                             const KnownKeys & knownKeys,
                             Ed25519KeyPair & myKeys,
                             string & clientPubKey)
    {
      bool  rc = false;
      if (keyStash.Get(myKeys)) {
        if (SendTo(myKeys.Id())) {
          string  clientId;
          if (ReceiveFrom(clientId)) {
            clientPubKey = knownKeys.Find(clientId);
            if (! clientPubKey.empty()) {
              rc = true;
            }
            else {
              Syslog(LOG_ERR, "client %s not known", clientId.c_str());
            }
          }
          else {
            Syslog(LOG_ERR, "Failed to read ID from client");
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to send ID to client");
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Client::ExchangeChallenges(const std::string & mySecretKey,
                                    const std::string & clientPubKey)
    {
      bool  rc = false;
      //  Send challenge to client
      Challenge  clientChallenge(true);
      if (SendTo(clientChallenge)) {
        //  Receive challenge from client
        Challenge  myChallenge;
        if (ReceiveFrom(myChallenge)) {
          //  Send my response
          ChallengeResponse  myResponse;
          if (myResponse.Create(mySecretKey, myChallenge)) {
            if (SendTo(myResponse)) {
              // Receive response from client
              ChallengeResponse  clientResponse;
              if (ReceiveFrom(clientResponse)) {
                if (clientResponse.Verify(clientPubKey, clientChallenge)) {
                  rc = true;
                }
              }
              else {
                Syslog(LOG_ERR, "Failed to read client challenge response");
              }
            }
            else {
              Syslog(LOG_INFO, "Failed to send challenge response to client");
            }
          }
        }
        else {
          Syslog(LOG_INFO, "Failed to read challenge from client");
        }
      }
      else {
        Syslog(LOG_INFO, "Failed to send challenge to client");
      }
      return rc;
    }
    

  }  // namespace Credence

}  // namespace Dwm

