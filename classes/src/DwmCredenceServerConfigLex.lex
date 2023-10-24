%{
  #include <map>
  #include <regex>

  #include "DwmIpv4Address.hh"
  #include "DwmIpv6Address.hh"
  #include "DwmSvnTag.hh"
  #include "DwmCredenceServerConfig.hh"
  #include "DwmCredenceServerConfigParse.hh"

  extern "C" {
    #include <stdarg.h>

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void credenceservercfgerror(const char *arg, ...)
    {
      va_list  ap;
      va_start(ap, arg);
      vfprintf(stderr, arg, ap);
      fprintf(stderr, ": '%s' at line %d\n", yytext, yylineno);
      return;
    }
  }

  static const Dwm::SvnTag svntag("@(#) $DwmPath$");

  //--------------------------------------------------------------------------
  //!  
  //--------------------------------------------------------------------------
  static const std::map<std::string,int>  g_configKeywords = {
    { "addresses",           ADDRESSES      },
    { "address",             ADDRESS        },
    { "allowedClients",      ALLOWEDCLIENTS },
    { "keyDirectory",        KEYDIRECTORY   },
    { "port",                PORT           },
    { "service",             SERVICE        }
  };

  //--------------------------------------------------------------------------
  //!  
  //--------------------------------------------------------------------------
  static bool IsKeyword(const std::string & s, int & token)
  {
    bool  rc = false;
    auto  it = g_configKeywords.find(s);
    if (g_configKeywords.end() != it) {
      token = it->second;
      rc = true;
    }
    return rc;
  }

  //--------------------------------------------------------------------------
  //!  
  //--------------------------------------------------------------------------
  static bool IsNumber(const std::string & s)
  {
    using std::regex, std::smatch;
    static regex  rgx("[0-9]+", regex::ECMAScript|regex::optimize);
    smatch        sm;
    return std::regex_match(s, sm, rgx);
  }

%}

%option noyywrap
%option prefix="credenceservercfg"
%option yylineno

%x x_quoted
        
%%

<INITIAL>#.*\n
<INITIAL>[^ \t\n\[\]{}=,;"]+       { if (IsNumber(yytext)) {
                                       credenceservercfglval.intVal = atoi(yytext);
                                       return INTEGER;
                                     }
                                     else {
                                       int  token;
                                       if (IsKeyword(yytext, token)) {
                                         return token;
                                       }
                                       else {
                                         credenceservercfglval.stringVal =
                                           new std::string(yytext);
                                         return STRING;
                                       }
                                     }
                                   }
<INITIAL>["]                       { BEGIN(x_quoted); }
<x_quoted>[^"]+                    { credenceservercfglval.stringVal =
                                       new std::string(yytext);
                                     return STRING; }
<x_quoted>["]                      { BEGIN(INITIAL); }
<INITIAL>[=,;\[\]\{\}]             { return yytext[0]; }
<INITIAL>[ \t\n]

%%
