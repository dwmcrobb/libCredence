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
//!  \file DwmCredenceKXKeyPair.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KXKeyPair class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include "DwmCredenceKXKeyPair.hh"
#include "DwmCredenceGenericHash.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    KXKeyPair::KXKeyPair()
    {
      uint8_t  pkbuf[crypto_box_PUBLICKEYBYTES];
      uint8_t  skbuf[crypto_box_SECRETKEYBYTES];
      randombytes_buf(skbuf, sizeof(skbuf));
      crypto_scalarmult_base(pkbuf, skbuf);
      _publicKey = string((const char *)pkbuf, crypto_box_PUBLICKEYBYTES);
      _secretKey = string((const char *)skbuf, crypto_box_SECRETKEYBYTES);
    }
      
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    KXKeyPair::~KXKeyPair()
    {
      _publicKey.Clear();
      _secretKey.Clear();
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const ShortString<255> & KXKeyPair::PublicKey() const
    { return _publicKey; }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const ShortString<255> & KXKeyPair::SecretKey() const
    { return _secretKey; }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    size_t KXKeyPair::PublicKeyMinimumStreamedLength() const
    { return (crypto_box_PUBLICKEYBYTES + 1); }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    string KXKeyPair::SharedKey(const string & theirPublicKey) const
    {
      string   rc;
      string   scalarmult_q;
      if (Utils::ScalarMult(_secretKey.Value(), theirPublicKey,
                            scalarmult_q)) {
        GenericHash<crypto_generichash_BYTES>  h;
        h.Update(scalarmult_q);
        if (_publicKey.Value() < theirPublicKey) {
          h.Update(_publicKey.Value());
          h.Update(theirPublicKey);
        }
        else {
          h.Update(theirPublicKey);
          h.Update(_publicKey.Value());
        }
        rc = h.Final();
      }
      return rc;
    }

  }  // namespace Credence

}  // namespace Dwm
