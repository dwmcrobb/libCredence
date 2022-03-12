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
//!  \file DwmCredenceNonce.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credende::Nonce class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCENONCE_HH_
#define _DWMCREDENCENONCE_HH_

extern "C" {
  #include <sodium.h>
}

#include <cstdint>
#include <iostream>

#include "DwmStreamIOCapable.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates a nonce for encryption.
    //------------------------------------------------------------------------
    class Nonce
      : public StreamIOCapable
    {
    public:
      //----------------------------------------------------------------------
      //!  Default constructor.  Initializes the nonce with random data
      //!  if @c init is true.
      //----------------------------------------------------------------------
      Nonce(bool init = true)
      {
        if (init) {
          randombytes_buf(_nonce, sizeof(_nonce));
        }
      }

      //----------------------------------------------------------------------
      //!  Reads the nonce from the given istream @c is.  Returns @c is.
      //----------------------------------------------------------------------
      std::istream & Read(std::istream & is)
      {
        if (is) {
          is.read((char *)_nonce, crypto_secretbox_NONCEBYTES);
        }
        return is;
      }

      //----------------------------------------------------------------------
      //!  Writes the nonce to the given ostream @c os.  Returns @c os.
      //----------------------------------------------------------------------
      std::ostream & Write(std::ostream & os) const
      {
        if (os) {
          os.write((const char *)_nonce, crypto_secretbox_NONCEBYTES);
        }
        return os;
      }
      
      //----------------------------------------------------------------------
      //!  Copy constructor.
      //----------------------------------------------------------------------
      Nonce(const Nonce &) = default;
      
      //----------------------------------------------------------------------
      //!  Returns a pointer to const of the encapsulated nonce data.
      //----------------------------------------------------------------------
      operator const uint8_t * () const   { return _nonce; }

    private:
      uint8_t  _nonce[crypto_secretbox_NONCEBYTES];
    };
      
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCENONCE_HH_
