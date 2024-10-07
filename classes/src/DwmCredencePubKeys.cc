//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2024
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
//!  \file DwmCredencePubKeys.cc
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include <fstream>

#include "DwmStreamIO.hh"
#include "DwmCredencePubKeys.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    PubKeys::PubKeys()
        : _myKey(), _knownKeys()
    {}
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool PubKeys::Load(const std::string & keyDir)
    {
      bool  rc = false;
      Clear();
      std::ifstream  is(keyDir + "./id_ed25519.pub");
      if (is) {
        std::string  id, keyType, encodedKey;
        is >> id >> keyType >> encodedKey;
        is.close();
        if ((! id.empty()) && (keyType == "ed25519")
            && (! encodedKey.empty())) {
          unsigned char  binaryKey[crypto_sign_ed25519_PUBLICKEYBYTES];
          if (sodium_base642bin(binaryKey, crypto_sign_ed25519_PUBLICKEYBYTES,
                                encodedKey.data(), encodedKey.size(),
                                nullptr, 0, nullptr,
                                sodium_base64_VARIANT_ORIGINAL) == 0) {
            _myKey.first = id;
            _myKey.second = encodedKey;
            _knownKeys = KnownKeys(keyDir);
            rc = true;
          }
        }
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void PubKeys::Clear()
    {
      _myKey.first.clear();
      _myKey.second.clear();
      _knownKeys.ClearKeys();
      return;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::istream & PubKeys::Read(std::istream & is)
    {
      if (is) {
        if (StreamIO::Read(is, _myKey)) {
          StreamIO::Read(is, _knownKeys);
        }
      }
      return is;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::ostream & PubKeys::Write(std::ostream & os) const
    {
      if (os) {
        if (StreamIO::Write(os, _myKey)) {
          StreamIO::Write(os, _knownKeys);
        }
      }
      return os;
    }
    
  }  // namespace Credence

}  // namespace Dwm
