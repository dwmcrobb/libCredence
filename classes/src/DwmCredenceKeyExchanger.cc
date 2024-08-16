//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022, 2023
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
//!  \file DwmCredenceKeyExchanger.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KeyExchanger class implementation
//---------------------------------------------------------------------------

#include "DwmStreamIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceKXKeyPair.hh"
#include "DwmCredenceKeyExchanger.hh"
#include "DwmCredenceShortString.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    static bool
    GetSetSocketNoDelayOption(boost::asio::ip::tcp::socket & sck,
                              boost::asio::ip::tcp::no_delay & orig,
                              boost::asio::ip::tcp::no_delay & noDelay)
    {
      bool  rc = false;
      boost::system::error_code  ec;
      sck.get_option(orig, ec);
      if (! ec) {
        sck.set_option(noDelay, ec);
        if (! ec) {
          rc = true;
        }
        else {
          Syslog(LOG_ERR, "sck.set_option(no_delay) failed");
        }
      }
      else {
        Syslog(LOG_ERR, "sck.get_option(no_delay) failed");
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KeyExchanger::ExchangeKeys(boost::asio::ip::tcp::iostream & s,
                                    std::string & agreedKey,
                                    std::chrono::milliseconds timeout)
    {
      bool  rc = false;
      agreedKey.clear();
      if (s.socket().is_open()) {
        boost::system::error_code  ec;
        boost::asio::ip::tcp::endpoint  endPoint =
          s.socket().remote_endpoint(ec);
        if (! ec) {
          KXKeyPair  kxKeys;
          if (StreamIO::Write(s, kxKeys.PublicKey())) {
            s.flush();
            if (Utils::WaitForBytesReady(s.socket(),
                                         kxKeys.PublicKeyMinimumStreamedLength(),
                                         timeout)) {
              ShortString  theirPubKey;
              if (StreamIO::Read(s, theirPubKey)) {
                agreedKey = kxKeys.SharedKey(theirPubKey.Value());
                rc = true;
              }
              else {
                FSyslog(LOG_ERR, "Failed to read public key from {}",
                        Utils::EndPointString(endPoint));
              }
            }
            else {
              FSyslog(LOG_ERR, "Peer at {} failed to send public key within"
                      " {} milliseconds",
                      Utils::EndPointString(endPoint), timeout.count());
            }
          }
          else {
            FSyslog(LOG_ERR, "Failed to send public key to {}",
                    Utils::EndPointString(endPoint));
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to get endpoint");
        }
      }
      else {
        Syslog(LOG_ERR, "socket is not open");
      }

      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KeyExchanger::
    ExchangeKeys(boost::asio::local::stream_protocol::iostream & s,
                 std::string & agreedKey,
                 std::chrono::milliseconds timeout)
    {
      bool  rc = false;
      agreedKey.clear();
      if (s.socket().is_open()) {
        boost::system::error_code  ec;
        boost::asio::local::stream_protocol::endpoint  endPoint =
          s.socket().remote_endpoint(ec);
        if (! ec) {
          KXKeyPair  kxKeys;
          if (StreamIO::Write(s, kxKeys.PublicKey())) {
            s.flush();
            if (Utils::WaitForBytesReady(s.socket(),
                                         kxKeys.PublicKeyMinimumStreamedLength(),
                                         timeout)) {
              ShortString  theirPubKey;
              if (StreamIO::Read(s, theirPubKey)) {
                agreedKey = kxKeys.SharedKey(theirPubKey.Value());
                rc = true;
              }
              else {
                FSyslog(LOG_ERR, "Failed to read public key from {}",
                        endPoint.path());
              }
            }
            else {
              FSyslog(LOG_ERR, "Peer at {} failed to send public key within"
                      " {} milliseconds",
                      endPoint.path(), timeout.count());
            }
          }
          else {
            FSyslog(LOG_ERR, "Failed to send public key to {}",
                    endPoint.path());
          }
        }
        else {
          Syslog(LOG_ERR, "Failed to get endpoint");
        }
      }
      else {
        Syslog(LOG_ERR, "socket is not open");
      }

      return rc;
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
