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
//!  \file DwmCredenceSessionEncryptor.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::SessionEncryptor class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include "DwmSysLogger.hh"
#include "DwmCredenceSessionEncryptor.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool SessionEncryptor::Encrypt(const std::string & message,
                                   const SessionKeyPair & keys,
                                   const SessionNonce & nonce,
                                   std::string & encryptedMessage)
    {
      bool     rc = false;
      size_t   cipherlen = message.size() + crypto_secretbox_MACBYTES;
      uint8_t  cipherbuf[cipherlen];
      if (crypto_secretbox_easy(cipherbuf, (const uint8_t *)message.data(),
                                message.size(), nonce,
                                (const uint8_t *)keys.TxKey().data())
          == 0) {
        encryptedMessage.assign((const char *)cipherbuf, cipherlen);
        rc = true;
      }
      else {
        encryptedMessage.clear();
        Syslog(LOG_ERR, "crypto_secretbox_easy() failed");
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool SessionEncryptor::Decrypt(const std::string & encryptedMessage,
                                   const SessionKeyPair & keys,
                                   const SessionNonce & nonce,
                                   std::string & message)
    {
      bool     rc = false;
      size_t   msglen = encryptedMessage.size() - crypto_secretbox_MACBYTES;
      uint8_t  msgbuf[msglen];
      if (crypto_secretbox_open_easy(msgbuf,
                                     (const uint8_t *)encryptedMessage.data(),
                                     encryptedMessage.size(), nonce,
                                     (const uint8_t *)keys.RxKey().data())
          == 0) {
        message.assign((const char *)msgbuf, msglen);
        rc = true;
      }
      else {
        message.clear();
        Syslog(LOG_ERR, "crypto_secretbox_open_easy() failed");
      }
      return rc;
    }
    

  }  // namespace Credence

}  // namespace Dwm
