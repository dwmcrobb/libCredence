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
//!  \file DwmCredenceKnownKeys.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KnownKeys class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEKNOWNKEYS_HH_
#define _DWMCREDENCEKNOWNKEYS_HH_

#include <iostream>
#include <map>
#include <shared_mutex>
#include <string>

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates the storage of a set of known public keys.  These
    //!  keys are stored in a file in a directory given as an argument to
    //!  the constructor.  By default, this directory is .credence in the
    //!  user's home directory and the file within that directory is named
    //!  known_keys.
    //------------------------------------------------------------------------
    class KnownKeys
    {
    public:
      //----------------------------------------------------------------------
      //!  Construct with the given storage directory @c dirName and file
      //!  name @c fileName within the storage directory.  i.e. the file at
      //!  path @c dirName/fileName will hold the public keys.
      //----------------------------------------------------------------------
      KnownKeys(const std::string & dirName = "~/.credence",
                const std::string & fileName = "known_keys");

      //----------------------------------------------------------------------
      //!  Copy constructor
      //----------------------------------------------------------------------
      KnownKeys(const KnownKeys & knownKeys);

      //----------------------------------------------------------------------
      //!  Copy assignment
      //----------------------------------------------------------------------
      KnownKeys & operator = (const KnownKeys & knownKeys);
      
      //----------------------------------------------------------------------
      //!  Returns the public key for the given key owner @c id on success.
      //!  Returns an empty string if no key is found for @c id.
      //----------------------------------------------------------------------
      std::string Find(const std::string & id) const;

      //----------------------------------------------------------------------
      //!  Reloads the keys from persistent storage.
      //----------------------------------------------------------------------
      void Reload();
      
      //----------------------------------------------------------------------
      //!  Returns a copy of the encapsulated keys.
      //----------------------------------------------------------------------
      std::map<std::string,std::string> Keys() const;

      //----------------------------------------------------------------------
      //!  Reads the keys from the given istream @c is, in machine-readable
      //!  form (for use with StreamIO from libDwm).  Returns @c is.  Note
      //!  that the key content is expected to be in binary form, not base64
      //!  encoded.
      //----------------------------------------------------------------------
      std::istream & Read(std::istream & is);
      
      //----------------------------------------------------------------------
      //!  Writes the keys to the given ostream @c os, in machine-readable
      //!  form (for use with StreamIO from libDwm).  Returns @c os.  Note
      //!  that key content is emitted in binary form, and is hence not
      //!  terminal or human friendly.
      //----------------------------------------------------------------------
      std::ostream & Write(std::ostream & os) const;

      //----------------------------------------------------------------------
      //!  Prints the keys in printable form (the same as the stored
      //!  file used by the constructor and Reload()) to the given ostream
      //!  @c os.  Returns @c os.  Note that key content is base64-encoded
      //!  when output to @c os.
      //----------------------------------------------------------------------
      friend std::ostream &
      operator << (std::ostream & os, const KnownKeys & knownKeys);

      //----------------------------------------------------------------------
      //!  Clears the keys.
      //----------------------------------------------------------------------
      void ClearKeys();
      
    private:
      std::string                        _dirName;
      std::string                        _fileName;
      mutable std::shared_mutex          _keysMtx;
      std::map<std::string,std::string>  _keys;

      bool LoadKeys();
    };
    
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEKNOWNKEYS_HH_
