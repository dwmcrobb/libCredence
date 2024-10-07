//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022, 2024
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
//!  \file DwmCredenceX25519KeyPair.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::X25519KeyPair class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include "DwmCredenceX25519KeyPair.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    X25519KeyPair::X25519KeyPair()
    {
      uint8_t  pk[crypto_box_PUBLICKEYBYTES], sk[crypto_box_SECRETKEYBYTES];
      crypto_box_keypair(pk, sk);
      _publicKey.assign((const char *)pk, crypto_box_PUBLICKEYBYTES);
      _secretKey.assign((const char *)sk, crypto_box_SECRETKEYBYTES);
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    X25519KeyPair::~X25519KeyPair()
    {
      Clear();
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    X25519KeyPair::X25519KeyPair(const Ed25519KeyPair & edkp)
    {
      uint8_t         x25519_pk[crypto_scalarmult_curve25519_BYTES];
      const uint8_t  *edkp_pk = (const uint8_t *)edkp.PublicKey().Key().data();
      if (crypto_sign_ed25519_pk_to_curve25519(x25519_pk, edkp_pk) == 0) {
        _publicKey.assign((const char *)x25519_pk,
                          crypto_scalarmult_curve25519_BYTES);
      }
      
      uint8_t         x25519_sk[crypto_scalarmult_curve25519_BYTES];
      const uint8_t  *edkp_sk = (const uint8_t *)edkp.SecretKey().Key().data();
      if (crypto_sign_ed25519_sk_to_curve25519(x25519_sk, edkp_sk) == 0) {
        _secretKey.assign((const char *)x25519_sk,
                          crypto_scalarmult_curve25519_BYTES);
      }
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const std::string & X25519KeyPair::PublicKey() const
    {
      return _publicKey;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const std::string & X25519KeyPair::SecretKey() const
    {
      return _secretKey;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void X25519KeyPair::Clear()
    {
      _publicKey.assign(_publicKey.size(), '\0');
      _publicKey.clear();
      _secretKey.assign(_secretKey.size(), '\0');
      _secretKey.clear();
      return;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool X25519KeyPair::operator == (const X25519KeyPair & xkp) const
    {
      return ((_publicKey == xkp._publicKey)
              && (_secretKey == xkp._secretKey));
    }
    
  }  // namespace Credence

}  // namespace Dwm
