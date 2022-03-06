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
//!  \file DwmCredenceChallenge.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Challenge class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include "DwmIO.hh"
#include "DwmCredenceSigner.hh"
#include "DwmCredenceChallenge.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Challenge::Challenge(bool init)
        : _challenge()
    {
      if (init) {
        uint8_t  buf[32];
        randombytes_buf((void *)buf, 32);
        _challenge.assign((const char *)buf, 32);
      }
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Challenge::operator const string & () const
    {
      return _challenge;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::istream & Challenge::Read(std::istream & is)
    {
      if (is) {
        IO::Read(is, _challenge);
      }
      return is;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::ostream & Challenge::Write(std::ostream & os) const
    {
      if (os) {
        IO::Write(os, _challenge);
        os.flush();
      }
      return os;
    }
    

  }  // namespace Credence

}  // namespace Dwm
