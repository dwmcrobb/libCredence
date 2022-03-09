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
//!  \file DwmCredenceShortString.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::ShortString class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCESHORTSTRING_HH_
#define _DWMCREDENCESHORTSTRING_HH_

#include <string>

#include "DwmStreamIOCapable.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    class ShortString
      : public StreamIOCapable
    {
    public:
      ShortString() = default;
      ShortString(const ShortString &) = default;
      ShortString & operator = (const ShortString &) = default;
      ShortString(const std::string & s);
      ShortString & operator = (const std::string & s);
      const std::string & Value() const;
      operator std::string () const
      { return _s; }
      
      std::istream & Read(std::istream & is) override;
      std::ostream & Write(std::ostream & os) const override;

      friend std::ostream & operator << (std::ostream & os,
                                         const ShortString & shortString);
      friend std::istream & operator >> (std::istream & is,
                                         ShortString & shortString);
      bool operator == (const ShortString & s) const;
      
    private:
      std::string  _s;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCESHORTSTRING_HH_
