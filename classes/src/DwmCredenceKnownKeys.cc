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
//!  \file DwmCredenceKnownKeys.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KnownKeys class implementation
//---------------------------------------------------------------------------

#include <fstream>
#include <regex>

#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    KnownKeys::KnownKeys(const string & dirName)
        : _dirName(dirName), _keysMtx()
    {
      static const regex  rgx("^~\\/.*");
      if (regex_match(_dirName, rgx)) {
        string  homeDir = Utils::UserHomeDirectory();
        if (! homeDir.empty()) {
          regex  rplrgx("^~");
          _dirName = regex_replace(_dirName, rplrgx, homeDir);
        }
      }
      LoadKeys();
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    KnownKeys::KnownKeys(const KnownKeys & knownKeys)
        : _dirName(knownKeys._dirName), _keysMtx()
    {
      LoadKeys();
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    string KnownKeys::Find(const string & id) const
    {
      string  rc;
      std::shared_lock  lck(_keysMtx);
      auto  it = _keys.find(id);
      if (it != _keys.end()) {
        rc = it->second;
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    map<string,string> KnownKeys::Keys() const
    {
      std::shared_lock  lck(_keysMtx);
      return map<string,string>(_keys);
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void KnownKeys::Reload()
    {
      LoadKeys();
      return;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KnownKeys::LoadKeys()
    {
      std::unique_lock  lck(_keysMtx);
      _keys.clear();
      ifstream  is(_dirName + "/known_keys");
      pair<string,string>  key;
      while (ReadKey(is, key)) {
        _keys[key.first] = key.second;
      }
      return (! _keys.empty());
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KnownKeys::ReadKey(istream & is, pair<string,string> & key)
    {
      bool  rc = false;
      if (is) {
        string  id, keyType, keystr;
        if (is >> id >> keyType >> keystr) {
          if ((keyType == "ed25519") && (! keystr.empty())) {
            key.first = id;
            key.second = Utils::Base642Bin(keystr);
            if (! key.second.empty()) {
              rc = true;
            }
          }
        }
      }
      return rc;
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
