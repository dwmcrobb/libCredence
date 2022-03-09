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
//!  \file DwmCredenceShortString.cc
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#include "DwmCredenceShortString.hh"

namespace Dwm {

  namespace Credence {
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    ShortString::ShortString(const std::string & s)
    {
      if (s.size() <= 255) {
        _s = s;
      }
      else {
        throw std::logic_error("Initializing string too long");
      }
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    ShortString & ShortString::operator = (const std::string & s)
    {
      if (s.size() <= 255) {
        _s = s;
      }
      else {
        throw std::logic_error("Initializing string too long");
      }
      return *this;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const std::string & ShortString::Value() const
    {
      return _s;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::istream & ShortString::Read(std::istream & is)
    {
      _s.clear();
      if (is) {
        uint8_t  len;
        if (is.read((char *)&len, sizeof(len))) {
          if (len) {
            char  buf[len];
            if (is.read(buf, len)) {
              _s.assign(buf, len);
            }
          }
        }
      }
      return is;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::ostream & ShortString::Write(std::ostream & os) const
    {
      if (os) {
        uint8_t  len = _s.size();
        if (os.write((char *)&len, sizeof(len))) {
          if (len) {
            os.write(_s.data(), _s.size());
          }
        }
      }
      return os;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::ostream & operator << (std::ostream & os,
                                const ShortString & shortString)
    {
      return (os << shortString._s);
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::istream & operator >> (std::istream & is,
                                ShortString & shortString)
    {
      shortString._s.clear();
      std::string  s;
      if (is >> s) {
        if (s.size() <= 255) {
          shortString._s = s;
        }
        else {
          throw std::logic_error("String too long");
        }
      }
      return is;
    }
    

  }  // namespace Credence

}  // namespace Dwm
