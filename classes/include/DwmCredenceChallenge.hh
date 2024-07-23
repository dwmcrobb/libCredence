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
//!  \file DwmCredenceChallenge.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Challenge class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCECHALLENGE_HH_
#define _DWMCREDENCECHALLENGE_HH_

#include "DwmCredenceShortString.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulate a challenge sent to a client or server to verify their
    //!  idendity during authentication.  The challenge consists of 32 bytes
    //!  of random data.
    //------------------------------------------------------------------------
    class Challenge
    {
    public:
      //----------------------------------------------------------------------
      //!  Default constructor.  If @c init is @c true, the content of the
      //!  challenge will be initialized with random data.  This is used
      //!  when the challenge will be transmitted.  If @c init is @c false,
      //!  the content of the challenge will not be initialized.  This is
      //!  used when we are intending to receive a challenge via the
      //!  Read() member.
      //----------------------------------------------------------------------
      Challenge(bool init = false);
      
      //----------------------------------------------------------------------
      //!  Copy constructor.
      //----------------------------------------------------------------------
      Challenge(const Challenge &) = default;
      
      //----------------------------------------------------------------------
      //!  Assignment operator.
      //----------------------------------------------------------------------
      Challenge & operator = (const Challenge &) = default;
      
      //----------------------------------------------------------------------
      //!  Returns a reference to the encapsulate challenge data.
      //----------------------------------------------------------------------
      operator const std::string & () const;
      
      //----------------------------------------------------------------------
      //!  Reads the challenge from the given istream @c is.  Returns @c is.
      //!  @c is normally a reference to an XChaChaPoly1305::Istream.
      //----------------------------------------------------------------------
      std::istream & Read(std::istream & is);
      
      //----------------------------------------------------------------------
      //!  Writes the challenge to the given ostream @c os.  Returns @c os.
      //!  @c os is normally a reference to an XChaChapoly1305::Ostream.
      //----------------------------------------------------------------------
      std::ostream & Write(std::ostream & os) const;
      
    private:
      ShortString  _challenge;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCECHALLENGE_HH_
