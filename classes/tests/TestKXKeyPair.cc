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
//!  \file TestKXKeyPair.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KXKeyPair unit tests
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include <iostream>

#include "DwmUnitAssert.hh"
#include "DwmCredenceKXKeyPair.hh"
#include "DwmCredenceUtils.hh"

using namespace std;
using namespace Dwm;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
string GenerateSharedKeyServer(const Credence::KXKeyPair & serverKeys,
                               const string & clientPublicKey)
{
  string   rc;
  uint8_t  scalarmult_q[crypto_scalarmult_BYTES];
  if (crypto_scalarmult(scalarmult_q,
                        (const uint8_t *)serverKeys.SecretKey().data(),
                        (const uint8_t *)clientPublicKey.data())) {
    crypto_generichash_state  h;
    uint8_t  sharedKey[crypto_generichash_BYTES] = {0};
    crypto_generichash_init(&h, NULL, 0U, sizeof sharedKey);
    crypto_generichash_update(&h, scalarmult_q, sizeof(scalarmult_q));
    crypto_generichash_update(&h, (const uint8_t *)clientPublicKey.data(),
                              clientPublicKey.size());
    crypto_generichash_update(&h,
                              (const uint8_t *)serverKeys.PublicKey().data(),
                              serverKeys.PublicKey().size());
    crypto_generichash_final(&h, sharedKey, sizeof(sharedKey));
    rc.assign((const char *)sharedKey, sizeof(sharedKey));
  }
  return rc;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
string GenerateSharedKeyClient(const Credence::KXKeyPair & clientKeys,
                               const string & serverPublicKey)
{
  string   rc;
  uint8_t  scalarmult_q[crypto_scalarmult_BYTES];
  if (crypto_scalarmult(scalarmult_q,
                        (const uint8_t *)clientKeys.SecretKey().data(),
                        (const uint8_t *)serverPublicKey.data())) {
    crypto_generichash_state  h;
    uint8_t  sharedKey[crypto_generichash_BYTES] = {0};
    crypto_generichash_init(&h, NULL, 0U, sizeof sharedKey);
    crypto_generichash_update(&h, scalarmult_q, sizeof(scalarmult_q));
    crypto_generichash_update(&h,
                              (const uint8_t *)clientKeys.PublicKey().data(),
                              clientKeys.PublicKey().size());
    crypto_generichash_update(&h,
                              (const uint8_t *)serverPublicKey.data(),
                              serverPublicKey.size());
    crypto_generichash_final(&h, sharedKey, sizeof(sharedKey));
    rc.assign((const char *)sharedKey, sizeof(sharedKey));
  }
  return rc;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  Credence::KXKeyPair  clientKeys, serverKeys;
  UnitAssert(clientKeys.PublicKey().size() == crypto_box_PUBLICKEYBYTES);
  UnitAssert(clientKeys.SecretKey().size() == crypto_box_SECRETKEYBYTES);
  UnitAssert(serverKeys.PublicKey().size() == crypto_box_PUBLICKEYBYTES);
  UnitAssert(serverKeys.SecretKey().size() == crypto_box_SECRETKEYBYTES);

  string clientSharedKey = clientKeys.ClientSharedKey(serverKeys.PublicKey());
  string serverSharedKey = serverKeys.ServerSharedKey(clientKeys.PublicKey());
  if (UnitAssert((! clientSharedKey.empty())
                 && (! serverSharedKey.empty()))) {
    UnitAssert(clientSharedKey == serverSharedKey);
  }

  if (Assertions::Total().Failed()) {
    Assertions::Print(cerr, true);
    return 1;
  }
  else {
    cout << Assertions::Total() << " passed" << endl;
  }
  return 0;
}

