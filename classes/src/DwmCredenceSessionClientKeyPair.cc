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
//!  \file DwmCredenceSessionClientKeyPair.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::SessionClientKeyPair class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include <cstdint>
#include <cstdlib>

#include "DwmCredenceKXKeyPair.hh"
#include "DwmCredenceSessionClientKeyPair.hh"

using namespace std;

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    SessionClientKeyPair::SessionClientKeyPair(const KXKeyPair & clientKXKeys,
                                               const string & serverPubKey)
    {
      unsigned char  client_rx[crypto_kx_SESSIONKEYBYTES];
      unsigned char  client_tx[crypto_kx_SESSIONKEYBYTES];

      const uint8_t  *mypk = (const uint8_t *)clientKXKeys.PublicKey().c_str();
      const uint8_t  *mysk = (const uint8_t *)clientKXKeys.SecretKey().c_str();
      const uint8_t  *serverpk = (const uint8_t *)serverPubKey.c_str();
      
      if (crypto_kx_client_session_keys(client_rx, client_tx,
                                        mypk, mysk, serverpk) != 0) {
        abort();
      }
      _receiveKey.assign((const char *)client_rx, crypto_kx_SESSIONKEYBYTES);
      _sendKey.assign((const char *)client_tx, crypto_kx_SESSIONKEYBYTES);
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    SessionClientKeyPair::~SessionClientKeyPair()
    {
      _receiveKey.assign(_receiveKey.size(), '\0');
      _sendKey.assign(_sendKey.size(), '\0');
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const std::string & SessionClientKeyPair::RxKey() const
    {
      return _receiveKey;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const std::string & SessionClientKeyPair::TxKey() const
    {
      return _sendKey;
    }
    
  }  // namespace Credence

}  // namespace Dwm
