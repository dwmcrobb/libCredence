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
//!  \file DwmCredenceEd25519Key.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Ed25519Key class implementation
//---------------------------------------------------------------------------

#include "DwmStreamIO.hh"
#include "DwmCredenceEd25519Key.hh"
#include "DwmCredenceShortString.hh"
#include "DwmCredenceKeyType.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    Ed25519Key::Ed25519Key(const std::string & id,
                           const std::string & key)
        : _id(id), _key(key)
    {}
    
    //------------------------------------------------------------------------
    std::istream & Ed25519Key::Read(std::istream & is)
    {
      _id.Clear();
      _key.Clear();
      ShortString<255>  id, key;
      if (StreamIO::Read(is, id)) {
        if (StreamIO::Read(is, key)) {
          _id = id;
          _key = key;
        }
      }
      return is;
    }

    //------------------------------------------------------------------------
    std::ostream & Ed25519Key::Write(std::ostream & os) const
    {
      if (StreamIO::Write(os, _id)) {
        StreamIO::Write(os, _key);
      }
      return os;
    }

    //------------------------------------------------------------------------
    std::ostream &
    operator << (std::ostream & os, const Ed25519Key & pk)
    {
      os << pk._id << " ed25519 " << Utils::Bin2Base64(pk._key.Value());
      return os;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void Ed25519Key::Clear()
    {
      _id.Clear();
      _key.Clear();
    }
    
    //------------------------------------------------------------------------
    std::istream & operator >> (std::istream & is, Ed25519Key & pk)
    {
      pk._id.Clear();
      pk._key.Clear();
      if (is) {
        ShortString<255>                     id;
        ShortString<MaxKeyTypeNameLength()>  keyType;
        ShortString<MaxKeyStringLength()>    key;
        try {
          is >> id >> keyType >> key;
        }
        catch (std::logic_error & ex) {
          is.setstate(std::ios_base::failbit);
          return is;
        }
        
        if ((! id.Value().empty())
            && (keyType.Value() == "ed25519")
            && (! key.Value().empty())) {
          pk._id = id.Value();
          pk._key = Utils::Base642Bin(key.Value());
        }
        else {
          is.setstate(std::ios_base::failbit);
          pk._id.Clear();
          pk._key.Clear();
        }
      }
      return is;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Ed25519Key::operator < (const Ed25519Key & k) const
    {
      if (_id < k._id) {
        return true;
      }
      else if ((_id == k._id) && (_key < k._key)) {
        return true;
      }
      return false;
    }

  }  // namespace Credence

}  // namespace Dwm
