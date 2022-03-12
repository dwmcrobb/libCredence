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
    //!  Encapsulates a string that is restricted to 255 bytes or less.
    //!  We use this to prevent a couple of memory resource DoS attacks on
    //!  a server during session initialization.
    //------------------------------------------------------------------------
    class ShortString
      : public StreamIOCapable
    {
    public:
      //----------------------------------------------------------------------
      //!  Default constructor.
      //----------------------------------------------------------------------
      ShortString() = default;
      
      //----------------------------------------------------------------------
      //!  Copy constructor.
      //----------------------------------------------------------------------
      ShortString(const ShortString &) = default;
      
      //----------------------------------------------------------------------
      //!  Assignment operator.
      //----------------------------------------------------------------------
      ShortString & operator = (const ShortString &) = default;
      
      //----------------------------------------------------------------------
      //!  Construct from the given string @c s.  Throws an exception if
      //!  s.size() is greater than 255.
      //----------------------------------------------------------------------
      ShortString(const std::string & s);
      
      //----------------------------------------------------------------------
      //!  Assign from the given string @c s.  Throws an exception if
      //!  s.size() is greater than 255 bytes.
      //----------------------------------------------------------------------
      ShortString & operator = (const std::string & s);
      
      //----------------------------------------------------------------------
      //!  Returns the contained string value.
      //----------------------------------------------------------------------
      const std::string & Value() const;
      
      //----------------------------------------------------------------------
      //!  Returns a copy of the contained string value.
      //----------------------------------------------------------------------
      operator std::string () const
      { return _s; }
      
      //----------------------------------------------------------------------
      //!  Reads the short string from the given istream @c is.  Returns
      //!  @c is.
      //----------------------------------------------------------------------
      std::istream & Read(std::istream & is) override;

      //----------------------------------------------------------------------
      //!  Writes the shirt string to the given ostream @c os.  Returns
      //!  @c os.
      //----------------------------------------------------------------------
      std::ostream & Write(std::ostream & os) const override;

      //----------------------------------------------------------------------
      //!  ostream operator <<
      //----------------------------------------------------------------------
      friend std::ostream & operator << (std::ostream & os,
                                         const ShortString & shortString);

      //----------------------------------------------------------------------
      //!  istream operator >>
      //!
      //!  Throws an exception if the string is longer than 255 characters.
      //!  Note that the string can not include whitespace.
      //----------------------------------------------------------------------
      friend std::istream & operator >> (std::istream & is,
                                         ShortString & shortString);

      //----------------------------------------------------------------------
      //!  operator ==
      //----------------------------------------------------------------------
      bool operator == (const ShortString & s) const;
      
    private:
      std::string  _s;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCESHORTSTRING_HH_
