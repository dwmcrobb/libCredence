//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022, 2024
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

#include "DwmStreamIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceEd25519PublicKey.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    KnownKeys::KnownKeys(const string & dirName, const string & fileName)
        : _dirName(dirName), _fileName(fileName), _keysMtx()
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
      std::shared_lock  lck(knownKeys._keysMtx);
      _keys = knownKeys._keys;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    KnownKeys & KnownKeys::operator = (const KnownKeys & knownKeys)
    {
      if (&knownKeys != this) {
        std::shared_lock  lck(knownKeys._keysMtx);
        std::unique_lock  mylck(_keysMtx);
        _dirName = knownKeys._dirName;
        _keys = knownKeys._keys;
      }
      return *this;
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
    std::istream & KnownKeys::Read(std::istream & is)
    {
      if (is) {
        std::unique_lock  lck(_keysMtx);
        StreamIO::Read(is, _keys);
      }
      return is;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::ostream & KnownKeys::Write(std::ostream & os) const
    {
      if (os) {
        std::shared_lock  lck(_keysMtx);
        StreamIO::Write(os, _keys);
      }
      return os;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::ostream &
    operator << (std::ostream & os, const KnownKeys & knownKeys)
    {
      std::shared_lock  lck(knownKeys._keysMtx);
      for (const auto & key : knownKeys._keys) {
        os << key.first << " ed25519 " << key.second << '\n';
      }
      return os;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void KnownKeys::ClearKeys()
    {
      std::unique_lock  lck(_keysMtx);
      _keys.clear();
      return;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KnownKeys::LoadKeys()
    {
      std::unique_lock  lck(_keysMtx);
      _keys.clear();
      ifstream  is(_dirName + '/' + _fileName);
      if (is) {
        while (is) {
          Ed25519PublicKey  pk;
          if (is >> pk) {
            _keys[pk.Id()] = pk.Key();
          }
          else if (is.eof() || is.bad()) {
            break;
          }
          else if (is.fail()) {
            is.clear();
            is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
          }
        }
        FSyslog(LOG_INFO, "Loaded {} keys from {}/{}",
                _keys.size(), _dirName, _fileName);
      }
      else {
        FSyslog(LOG_ERR, "Failed to open {}/{}", _dirName, _fileName);
      }
      return (! _keys.empty());
    }

  }  // namespace Credence

}  // namespace Dwm
