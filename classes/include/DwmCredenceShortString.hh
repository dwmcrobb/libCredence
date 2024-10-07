//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022, 2023, 2024
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

#include "DwmStreamIO.hh"
#include "DwmSysLogger.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates a string that is restricted to LEN bytes or less.
    //!  We use this to prevent a couple of memory resource DoS attacks on
    //!  a server during session initialization.
    //------------------------------------------------------------------------
    template <size_t LEN>
    class ShortString
    {
    public:
      static constexpr size_t _size = LEN;

      //----------------------------------------------------------------------
      //!  Default constructor.
      //----------------------------------------------------------------------
      ShortString() : _s()  { }
      
      //----------------------------------------------------------------------
      //!  Copy constructor.
      //----------------------------------------------------------------------
      ShortString(const ShortString & ss) = default;

      //----------------------------------------------------------------------
      //!  Assignment operator.
      //----------------------------------------------------------------------
      ShortString & operator = (const ShortString & ss) = default;

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      template <size_t T>
      void Assign(const ShortString<T> & ss)
        requires (ShortString<T>::_size <= LEN)
      {
        _s = ss.Value();
        return;
      }

      //----------------------------------------------------------------------
      //!  Construct from the given string @c s.  Throws an exception if
      //!  s.size() is greater than LEN.
      //----------------------------------------------------------------------
      ShortString(const std::string & s)
      {
        if (s.size() <= LEN) {
          _s = s;
        }
        else {
          throw std::logic_error("Initializing string too long");
        }
      }

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      ShortString(const char *s)
          : ShortString(std::string(s))
      { }

#if 0
      //----------------------------------------------------------------------
      //!  Assign from the given string @c s.  Throws an exception if
      //!  s.size() is greater than LEN bytes.
      //----------------------------------------------------------------------
      ShortString & operator = (const std::string & s)
      {
        if (s.size() <= LEN) {
          _s = s;
        }
        else {
          throw std::logic_error("Initializing string too long");
        }
        return *this;
      }
#endif
      
      //----------------------------------------------------------------------
      //!  Destructor.
      //----------------------------------------------------------------------
      ~ShortString() = default;
      
      //----------------------------------------------------------------------
      //!  Returns the contained string value.
      //----------------------------------------------------------------------
      const std::string & Value() const  { return _s; }
      
      //----------------------------------------------------------------------
      //!  Returns a copy of the contained string value.
      //----------------------------------------------------------------------
      explicit operator std::string () const
      { return _s; }

      template <typename T> struct SizeType { using type = T; };
      template <size_t n> static constexpr auto TypeForSizeFn()
      {
        if constexpr (0xff >= n)        { return SizeType<uint8_t>{};  }
        else if constexpr (0xffff <= n) { return SizeType<uint16_t>{}; }
        else                            { return SizeType<uint32_t>{}; }
      }
      template <size_t N>
      using TypeFromSize = typename decltype(TypeForSizeFn<N>())::type;
      
      //----------------------------------------------------------------------
      //!  Reads the short string from the given istream @c is.  Returns
      //!  @c is.
      //----------------------------------------------------------------------
      std::istream & Read(std::istream & is)
      {
        _s.clear();
        if (is) {
          TypeFromSize<LEN>  len;
          if (StreamIO::Read(is, len)) {
            if (len) {
              try {
                _s.resize(len);
                is.read(_s.data(), len);
              }
              catch (...) {
                is.setstate(std::ios_base::badbit);
                FSyslog(LOG_ERR, "Failed to allocate {} bytes", len);
              }
            }
          }
        }
        return is;
      }

      //----------------------------------------------------------------------
      //!  Writes the short string to the given ostream @c os.  Returns
      //!  @c os.
      //----------------------------------------------------------------------
      std::ostream & Write(std::ostream & os) const
      {
        if (os) {
          TypeFromSize<LEN>  len = _s.size();
          if (StreamIO::Write(os, len)) {
            if (len) {
              os.write(_s.data(), _s.size());
            }
          }
        }
        return os;
      }

      //----------------------------------------------------------------------
      //!  ostream operator <<
      //----------------------------------------------------------------------
      friend std::ostream & operator << (std::ostream & os,
                                         const ShortString & shortString)
      {
        return (os << shortString._s);
      }

      //----------------------------------------------------------------------
      //!  istream operator >>
      //!
      //!  Throws an exception if the string is longer than LEN characters.
      //!  Note that the string can not include whitespace.
      //----------------------------------------------------------------------
      friend std::istream & operator >> (std::istream & is,
                                         ShortString & shortString)
      {
        shortString._s.clear();
        std::string  s;
        if (is >> s) {
          if (s.size() <= LEN) {
            shortString._s = s;
          }
          else {
            throw std::logic_error("String too long");
          }
        }
        return is;
      }

      //----------------------------------------------------------------------
      //!  operator ==
      //----------------------------------------------------------------------
      bool operator == (const ShortString & s) const
      {
        return (s._s == _s);
      }

      //----------------------------------------------------------------------
      //!  operator <
      //----------------------------------------------------------------------
      bool operator < (const ShortString & s) const
      {
        return (_s < s._s);
      }
      
      //----------------------------------------------------------------------
      //!  Clears the contents of the ShortString.
      //----------------------------------------------------------------------
      void Clear()
      {
        _s.assign(_s.size(), '\0');
        _s.clear();
        return;
      }
      
    private:
      std::string             _s;
    };
    
  }  // namespace Credence

}  // namespace Dwm


#endif  // _DWMCREDENCESHORTSTRING_HH_
