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
//!  \file DwmCredenceXChaCha20Poly1305InBuffer.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::XChaCha20Poly1305::InBuffer class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include <cstring>
#include <boost/asio.hpp>

#include "DwmPortability.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceXChaCha20Poly1305.hh"
#include "DwmCredenceXChaCha20Poly1305InBuffer.hh"

namespace Dwm {

  namespace Credence {

    namespace XChaCha20Poly1305 {

      using namespace std;
      
      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      InBuffer::InBuffer(std::istream & is, const std::string & key)
          : _is(is)
      {
        if (crypto_generichash_BYTES <= key.size()) {
          _key = key;
        }
        else {
          throw std::logic_error("Key not long enough!");
        }
      
        _buffer = nullptr;
        setg(0, 0, 0);
      }
    
      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      InBuffer::int_type InBuffer::underflow()
      {
        int_type  rc = traits_type::eof();
        if (gptr() < egptr()) {
          rc = traits_type::to_int_type(*gptr());
        }
        else if (Reload() > 0) {
          rc = traits_type::to_int_type(*gptr());
        }
        return rc;
      }

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      int InBuffer::Reload()
      {
        int  rc = -1;
        Nonce   nonce;
        string  cipherText;
        if (LoadNonceAndCipherText(nonce, cipherText)) {
          size_t  bufLen =
            cipherText.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
          //  NOTE: make_unique will throw an exception on failure, which
          //  would normally be caught by the istream and used to set badbit
          //  on the istream.
          try {
            _buffer = std::make_unique<char_type[]>(bufLen);
            string  msg;
            if (Decrypt(msg, cipherText, nonce, _key)) {
              rc = bufLen;
              memcpy(_buffer.get(), msg.data(), bufLen);
              setg(_buffer.get(), _buffer.get(),
                   _buffer.get() + bufLen);
            }
            else {
              Syslog(LOG_ERR, "Decrypt() of %zu bytes failed!",
                     cipherText.size());
              throw std::ios_base::failure("Decryption failed");
            }
          }
          catch (...) {
            Syslog(LOG_ERR, "Exception making buffer of %zu bytes",
                   bufLen);
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to read message");
          throw std::ios_base::failure("Failed to read message");
        }
        if (rc < 0) {
          setg(0, 0, 0);
        }
        return rc;
      }

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      bool InBuffer::LoadNonceAndCipherText(Nonce & nonce,
                                            std::string & cipherText)
      {
        bool  rc = false;
        if (nonce.Read(_is)) {
          uint64_t  msgLen;
          if (_is.read((char *)&msgLen, sizeof(msgLen))) {
            msgLen = be64toh(msgLen);
            try {
              cipherText.resize(msgLen);
              if (_is.read(cipherText.data(), msgLen)) {
                rc = true;
              }
              else {
                Syslog(LOG_DEBUG, "Failed to read cipherText");
              }
            }
            catch (...) {
              Syslog(LOG_ERR, "Failed to allocate %llu bytes", msgLen);
            }
          }
          else {
            Syslog(LOG_DEBUG, "Failed to read cipher text length");
          }
        }
        else {
          try {
            boost::asio::ip::tcp::iostream & bais =
              dynamic_cast<boost::asio::ip::tcp::iostream &>(_is);
            if ((bais.error() == boost::asio::error::eof)
                || (bais.error() == boost::asio::error::connection_reset)) {
              Syslog(LOG_DEBUG, "Connection lost");
            }
            else {
              Syslog(LOG_DEBUG, "Failed to read nonce");
            }
          }
          catch (...) {
            Syslog(LOG_DEBUG, "Failed to read nonce");
          }
        }
        return rc;
      }
    
    }  // namespace XChaCha20Poly1305

  }  // namespace Credence

}  // namespace Dwm
