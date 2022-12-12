include ../../Makefile.vars

ALLINC       = -I../include ${DWMINCS}
LTCLEAN      = ${LIBTOOL} --mode=clean rm -f
LTCOMPILE    = ${LIBTOOL} --mode=compile --tag=CXX ${CXX}
LTINSTALL    = ${LIBTOOL} --mode=install ../../install-sh
LTLINK       = ${LIBTOOL} --tag=CXX --mode=link ${CXX}
LTUNINSTALL  = ${LIBTOOL} --mode=uninstall rm -f
OBJFILESNP   = DwmCredenceAuthenticator.o \
               DwmCredenceChallenge.o \
               DwmCredenceChallengeResponse.o \
               DwmCredenceEd25519KeyPair.o \
               DwmCredenceKeyExchanger.o \
               DwmCredenceKeyStash.o \
               DwmCredenceKnownKeys.o \
               DwmCredenceKXKeyPair.o \
               DwmCredencePeer.o \
               DwmCredenceServerConfig.o \
               DwmCredenceShortString.o \
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
OBJFILES     = $(OBJFILESNP:%=../obj/%)
SHARED_OBJFILES = $(OBJFILES:%.o=%.lo)
OBJDEPS      = $(OBJFILESNP:%.o=deps/%_deps)
shlib_version = $(shell ../../getvers.sh -s)

all: ../lib/libDwmCredence.la

../lib/libDwmCredence.la: ${SHARED_OBJFILES}
	${LTLINK} -o $@ $^ -rpath ${INSTALLPREFIX}/lib -version-info ${shlib_version} ${LDFLAGS} ${DWMLIBS} ${SODIUMLIB}

#  dependency rule
deps/%_deps: %.cc
	@echo "making dependencies for $<"
	@set -e; \
	${CXX} -MM ${CXXFLAGS} ${PTHREADCXXFLAGS} ${ALLINC} -c $< | \
	 sed 's/\($*\)\.o[ :]*/\1.o $(@D)\/$(@F) : /g' > $@ ; [ -s $@ ] || \
	 rm -f $@

#  only include dependency makefiles if target is not 'clean' or 'distclean'
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
-include ${OBJDEPS}
endif
endif

../obj/%.lo ../obj/%.o: %.cc deps/%_deps
	${LTCOMPILE} ${CXXFLAGS} ${PTHREADCXXFLAGS} ${ALLINC} -c $< -o $@

tarprep: ${TARDIR}/lib/libDwmCredence.la

${TARDIR}/lib/libDwmCredence.la: ../lib/libDwmCredence.la
	${LTINSTALL} -c $< ${TARDIR}/lib/libDwmCredence.la

clean:: clean-tarprep
	${LTCLEAN} ../lib/libDwmCredence.la ${SHARED_OBJFILES}

distclean:: clean
	rm -f deps/*_deps

clean-tarprep::
	${LTUNINSTALL} ${TARDIR}/lib/libDwmCredence.la

