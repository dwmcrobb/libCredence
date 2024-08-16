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
//!  \file DwmCredenceSigner.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Signer class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include <cstdlib>

#include "DwmCredenceSigner.hh"
#include "DwmSysLogger.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Signer::Sign(const string & message,
                      const string & signingKey,
                      string & signedMessage)
    {
      bool  rc = false;
      if (! signingKey.empty()) {
        size_t    buflen = crypto_sign_BYTES + message.size();
        uint8_t  *buf = (uint8_t *)calloc(1, buflen);
        if (buf) {
          unsigned long long  signedMsgLen;
          if (crypto_sign(buf, &signedMsgLen,
                          (const uint8_t *)message.data(), message.size(),
                          (uint8_t *)signingKey.data()) == 0) {
            if (signedMsgLen <= buflen) {
              signedMessage.assign((const char *)buf, signedMsgLen);
              rc = true;
            }
            else {
              Syslog(LOG_ERR, "Signed message length too long!!!");
            }
          }
          else {
            Syslog(LOG_ERR, "crypto_sign() failed");
          }
          free(buf);
        }
        else {
          FSyslog(LOG_ERR, "Failed to allocate {} bytes for signed messsage",
                  buflen);
        }
      }
      else {
        Syslog(LOG_ERR, "Empty signing key");
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Signer::Open(const string & signedMessage,
                      const string & publicKey,
                      string & message)
    {
      bool      rc = false;
      size_t    buflen = signedMessage.size() - crypto_sign_BYTES;
      uint8_t  *buf = (uint8_t *)calloc(1, buflen);
      if (buf) {
        unsigned long long  unsignedMsgLen;
        if (crypto_sign_open(buf, &unsignedMsgLen,
                             (const uint8_t *)signedMessage.data(),
                             signedMessage.size(),
                             (const uint8_t *)publicKey.data()) == 0) {
          if (unsignedMsgLen <= buflen) {
            message.assign((const char *)buf, unsignedMsgLen);
            rc = true;
          }
          else {
            Syslog(LOG_ERR, "Message length too long!!!");
          }
        }
        else {
          Syslog(LOG_ERR, "crypto_sign_open() failed");
        }
        free(buf);
      }
      else {
        FSyslog(LOG_ERR, "Failed to allocate {} bytes for message", buflen);
      }
      return rc;
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
