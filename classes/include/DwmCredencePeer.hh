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
//!  \file DwmCredencePeer.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Peer class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEPEER_HH_
#define _DWMCREDENCEPEER_HH_

#include <boost/asio.hpp>

#include "DwmStreamIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceKeyStash.hh"
#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceXChaCha20Poly1305Istream.hh"
#include "DwmCredenceXChaCha20Poly1305Ostream.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    class Peer
    {
    public:
      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      Peer(boost::asio::ip::tcp::socket && s);

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      bool Authenticate(const KeyStash & keyStash,
                        const KnownKeys & knownKeys);

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      template <typename T>
      bool Send(const T & msg)
      {
        bool  rc = false;
        if (_xos) {
          if (StreamIO::Write(*_xos, msg)) {
            if (_xos->flush()) {
              rc = true;
            }
            else {
              Syslog(LOG_ERR, "Failed to flush encrypted stream");
            }
          }
          else {
            Syslog(LOG_ERR, "Failed to send message");
          }
        }
        return rc;
      }
      
      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      template <typename T>
      bool Receive(T & msg)
      {
        bool  rc = false;
        if (_xos) {
          if (StreamIO::Read(*_xis, msg)) {
            rc = true;
          }
          else {
            Syslog(LOG_ERR, "Failed to receive message");
          }
        }
        return rc;
      }

    private:
      boost::asio::ip::tcp::iostream               _ios;
      std::string                                  _theirId;
      std::unique_ptr<XChaCha20Poly1305::Istream>  _xis;
      std::unique_ptr<XChaCha20Poly1305::Ostream>  _xos;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEPEER_HH_
