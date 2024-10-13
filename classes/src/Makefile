include ../../Makefile.vars

ALLINC      := -I../include ${DWMINCS}
DEPSDIR     := deps
LTCLEAN     := ${LIBTOOL} --quiet --mode=clean rm -f
LTCOMPILE   := ${LIBTOOL} --quiet --mode=compile --tag=CXX ${CXX}
LTINSTALL   := ${LIBTOOL} --mode=install ../../install-sh
LTLINK      := ${LIBTOOL} --quiet --tag=CXX --mode=link ${CXX}
LTUNINSTALL := ${LIBTOOL} --quiet --mode=uninstall rm -f
OBJDIR      := ../obj
OBJFILESNP   = DwmCredenceAuthenticator.o \
               DwmCredenceChallenge.o \
               DwmCredenceChallengeResponse.o \
               DwmCredenceEd25519KeyPair.o \
               DwmCredenceKeyExchanger.o \
               DwmCredenceKeyStash.o \
               DwmCredenceKnownKeys.o \
               DwmCredenceKXKeyPair.o \
               DwmCredencePeer.o \
               DwmCredenceEd25519Key.o \
               DwmCredencePubKeys.o \
               DwmCredenceServerConfigLex.o \
               DwmCredenceServerConfigParse.o \
               DwmCredenceSigner.o \
               DwmCredenceUtils.o \
               DwmCredenceVersion.o \
               DwmCredenceX25519KeyPair.o \
               DwmCredenceXChaCha20Poly1305.o \
               DwmCredenceXChaCha20Poly1305InBuffer.o \
               DwmCredenceXChaCha20Poly1305OutBuffer.o
ifeq ($(MAKECMDGOALS),tarprep)
OBJFILESNP   += DwmCredenceVersion.o
endif
OBJFILES        = $(OBJFILESNP:%=${OBJDIR}/%)
SHARED_OBJFILES = $(OBJFILES:%.o=%.lo)
OBJDEPS         = $(OBJFILESNP:%.o=${DEPSDIR}/%_deps)
shlib_version   = $(shell ../../getvers.sh -s)

#-----------------------------------------------------------------------------
define MakeDep
${DEPSDIR}/%_deps: %.cc
	@echo "making dependencies for $$<"
	@set -e; \
	${CXX} -MM ${CXXFLAGS} ${ALLINC} -c $$< | \
	 sed 's/\($$*\)\.o[ :]*/$(subst /,\/,$(1))\/\1.o $(subst /,\/,$(1))\/\1.lo $$(@D)\/$$(@F) : /g' > $$@ ; [ -s $$@ ] || \
	 rm -f $$@

#  only include dependency makefiles if target is not 'clean' or 'distclean'
ifneq ($(MAKECMDGOALS),clean)
  ifneq ($(MAKECMDGOALS),distclean)
    -include ${OBJDEPS}
  endif
endif
endef

#-----------------------------------------------------------------------------
define Compile
 @echo compiling $(1) ; \
 cxx_cmd="${LTCOMPILE} ${CXXFLAGS} ${ALLINC} -c $(1) -o $(2)"; \
 cxx_cmd_out=`$${cxx_cmd} 2>&1`; \
 if [ $$? -ne 0 ]; then \
   printf "%s\n%s\n" "$${cxx_cmd}" "$${cxx_cmd_out}"; \
   exit 1; \
 fi ; \
 echo done compiling $(1)
endef

#-----------------------------------------------------------------------------
define LinkLibraries
 @printf "creating %s ..." $(1)
 @link_cmd="${LTLINK} -o $(1) ${SHARED_OBJFILES} -rpath ${INSTALLPREFIX}/lib -version-info ${shlib_version} ${LDFLAGS} ${DWMLIBSONLY} ${SODIUMLIB}"; \
 link_cmd_out=`$${link_cmd} 2>&1`; \
 if [ $$? -ne 0 ]; then \
   printf "%s\n%s\n" "$${link_cmd}" "$${link_cmd_out}"; \
   exit 1; \
 fi
 @printf " done\n"
endef

#-----------------------------------------------------------------------------

all: ../lib/libDwmCredence.la

../lib/libDwmCredence.la: ${SHARED_OBJFILES}
	$(call LinkLibraries,$@)

#  dependencies
$(eval $(call MakeDep,${OBJDIR}))

${OBJDIR}/%.lo ${OBJDIR}/%.o: %.cc ${DEPSDIR}/%_deps
	$(call Compile,$<,$@)

DwmCredenceServerConfigLex.cc: DwmCredenceServerConfigLex.lex DwmCredenceServerConfigParse.hh
	flex -o$@ $<

DwmCredenceServerConfigParse.hh: DwmCredenceServerConfigParse.cc

DwmCredenceServerConfigParse.cc: DwmCredenceServerConfigParse.y
	bison -d -o$@ $<

tarprep: ${TARDIR}/lib/libDwmCredence.la

${TARDIR}/lib/libDwmCredence.la: ../lib/libDwmCredence.la
	${LTINSTALL} -c $< ${TARDIR}/lib/libDwmCredence.la

clean:: clean-tarprep
	@${LTCLEAN} ../lib/libDwmCredence.la ${SHARED_OBJFILES}
	@${LTCLEAN} DwmCredenceServerConfigParse.hh \
	  DwmCredenceServerConfigParse.cc DwmCredenceServerConfigLex.cc

distclean:: clean
	rm -f ${DEPSDIR}/*_deps

clean-tarprep::
	@${LTUNINSTALL} ${TARDIR}/lib/libDwmCredence.la

