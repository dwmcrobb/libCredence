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
//!  \file DwmCredenceKeyType.hh
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEKEYTYPE_HH_
#define _DWMCREDENCEKEYTYPE_HH_

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    enum class KeyTypeEnum {
      e_keyTypeNone    = 0,
      e_keyTypeEd25519 = 1
    };

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    typedef struct {
      const std::string  name;
      const KeyTypeEnum  type;
      const size_t       maxKeyStringLen;
    } KeyTypeInfo;

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    constexpr std::array<KeyTypeInfo,1>  sg__keyTypes__ {
      { std::string{"ed25519"}, KeyTypeEnum::e_keyTypeEd25519, 255 }
    };
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    consteval size_t MaxKeyTypeNameLength()
    {
      constexpr auto it =
        std::max_element(std::cbegin(sg__keyTypes__),
                         std::cend(sg__keyTypes__),
                         [] (const auto & a, const auto & b)
                         { return a.name.size() < b.name.size(); });
      return it->name.size();
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    consteval size_t MaxKeyStringLength()
    {
      constexpr auto it =
        std::max_element(std::cbegin(sg__keyTypes__),
                         std::cend(sg__keyTypes__),
                         [] (const auto & a, const auto & b)
                         { return a.maxKeyStringLen < b.maxKeyStringLen; });
      return it->maxKeyStringLen;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    KeyTypeEnum KeyType(const std::string & name)
    {
      auto it =
        std::find_if(std::cbegin(sg__keyTypes__), std::cend(sg__keyTypes__),
                     [&] (const auto & e) { return (e.name == name); });
      return (it != std::cend(sg__keyTypes__)
              ? it->type : KeyTypeEnum::e_keyTypeNone);
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool IsValidKeyType(const std::string & name)
    {
      return (KeyType(name) != KeyTypeEnum::e_keyTypeNone);
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    constexpr bool IsValidKeyType(KeyTypeEnum kte)
    {
      return (std::find_if(std::cbegin(sg__keyTypes__),
                           std::cend(sg__keyTypes__),
                           [=] (const auto & e) { return (e.type == kte); })
              != std::cend(sg__keyTypes__));
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    size_t MaxKeyStringLength(KeyTypeEnum kte)
    {
      auto it =
        std::find_if(std::cbegin(sg__keyTypes__), std::cend(sg__keyTypes__),
                     [=] (const auto & e) { return (e.type == kte); });
      return (it != std::cend(sg__keyTypes__) ? it->maxKeyStringLen : 0);
    }
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEKEYTYPE_HH_
