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
//!  \file DwmCredenceKeyStash.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KeyStash class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEKEYSTASH_HH_
#define _DWMCREDENCEKEYSTASH_HH_

#include "DwmCredenceEd25519KeyPair.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    class KeyStash
    {
    public:
      KeyStash(const std::string & dirName = "~/.credence");
      const std::string & DirName() const;
      bool Save(const Ed25519KeyPair & edkp) const;
      bool Get(Ed25519KeyPair & edkp) const;
      
    private:
      std::string  _dirName;

      bool SavePublicKey(const Ed25519KeyPair & edkp) const;
      bool SaveSecretKey(const Ed25519KeyPair & edkp) const;
      bool GetPublicKey(Ed25519KeyPair & edkp) const;
      bool GetSecretKey(Ed25519KeyPair & edkp) const;
      bool MakeStashDir() const;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEKEYSTASH_HH_
