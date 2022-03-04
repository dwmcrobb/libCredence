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
//!  \file DwmCredenceGenericHash.hh
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEGENERICHASH_HH_
#define _DWMCREDENCEGENERICHASH_HH_

extern "C" {
  #include <sodium.h>
}

#include <cstdint>
#include <string>

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Class template that wraps sodium's crypto_generichash_* functions.
    //!  The template paramater @c OutLen is the desired length (in bytes) of
    //!  the hash returned by Final().
    //------------------------------------------------------------------------
    template <size_t OutLen>
    class GenericHash
    {
    public:
      //----------------------------------------------------------------------
      //!  Initializes the hash.
      //----------------------------------------------------------------------
      GenericHash(const std::string & key = "")
      {
        const uint8_t  *kp =
          (key.empty() ? nullptr : (const uint8_t *)key.data());
        crypto_generichash_init(&_h, kp, key.size(), OutLen);
      }
      
      //----------------------------------------------------------------------
      //!  Updates the hash.
      //----------------------------------------------------------------------
      void Update(const std::string & chunk)
      {
        crypto_generichash_update(&_h, (const uint8_t *)chunk.data(),
                                  chunk.size());
        return;
      }
        
      //----------------------------------------------------------------------
      //!  Returns the final hash.
      //----------------------------------------------------------------------
      std::string Final()
      {
        uint8_t  finalbuf[OutLen] = {0};
        crypto_generichash_final(&_h, finalbuf, sizeof(finalbuf));
        return std::string((const char *)finalbuf, OutLen);
      }
      
    private:
      crypto_generichash_state  _h;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEGENERICHASH_HH_
