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
//!  \file DwmCredenceXChaCha20Poly1305.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::XChaCha20Poly1305 function implementations
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include "DwmSysLogger.hh"
#include "DwmCredenceXChaCha20Poly1305.hh"

namespace Dwm {

  namespace Credence {

    namespace XChaCha20Poly1305 {

    using namespace std;
    
      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      bool Encrypt(string & cipherText, const string & message,
                   const Nonce & nonce, const string & secretKey)
      {
        constexpr auto  xcc20p1305enc =
          crypto_aead_xchacha20poly1305_ietf_encrypt;
        
        bool  rc = false;
        unsigned long long  cbuflen =
          message.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        try {
          cipherText.resize(cbuflen);
          if (xcc20p1305enc((uint8_t *)cipherText.data(), &cbuflen,
                            (const uint8_t *)message.data(),
                            message.size(),
                            nullptr, 0,
                            nullptr, nonce,
                            (const uint8_t *)secretKey.data())
              == 0) {
            rc = true;
          }
          else {
            Syslog(LOG_ERR, "xcc20p1305enc() failed in Encrypt()");
            cipherText.clear();
          }
        }
        catch (const std::exception & ex) {
          Syslog(LOG_ERR, "Got exception in Encrypt(): %s", ex.what());
        }
        catch (...) {
          Syslog(LOG_ERR, "Got exception in Encrypt()");
        }
        return rc;
      }

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      bool Decrypt(string & message, const string & cipherText,
                   const Nonce & nonce, const string & secretKey)
      {
        constexpr auto  xcc20p1305dec =
          crypto_aead_xchacha20poly1305_ietf_decrypt;
      
        bool  rc = false;
        unsigned long long  msglen =
          cipherText.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        try {
          message.resize(msglen);
          if (xcc20p1305dec((uint8_t *)message.data(), &msglen, nullptr,
                            (const uint8_t *)cipherText.data(),
                            cipherText.size(),
                            nullptr, 0,
                            nonce, (const uint8_t *)secretKey.data())
              == 0) {
            rc = true;
          }
          else {
            Syslog(LOG_ERR, "xcc20p1305dec() failed in Decrypt()");
            message.clear();
          }
        }
        catch (const std::exception & ex) {
          Syslog(LOG_ERR, "Got exception in Encrypt(): %s", ex.what());
        }
        catch (...) {
          message.clear();
          Syslog(LOG_ERR, "Got exception in Decrypt()");
        }
        
        return rc;
      }
    

    }  // namespace XChaCha20Poly1305
    
  }  // namespace Credence

}  // namespace Dwm
