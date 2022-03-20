include ../../Makefile.vars

ALLINC       = -I../include ${DWMINCS}
OBJFILESNP   = DwmCredenceAuthenticator.o \
               DwmCredenceChallenge.o \
               DwmCredenceChallengeResponse.o \
               DwmCredenceEd25519KeyPair.o \
               DwmCredenceKeyExchanger.o \
               DwmCredenceKeyStash.o \
               DwmCredenceKnownKeys.o \
               DwmCredenceKXKeyPair.o \
               DwmCredencePeer.o \
               DwmCredenceShortString.o \
               DwmCredenceSigner.o \
               DwmCredenceUtils.o \
               DwmCredenceX25519KeyPair.o \
               DwmCredenceXChaCha20Poly1305.o \
               DwmCredenceXChaCha20Poly1305InBuffer.o \
               DwmCredenceXChaCha20Poly1305OutBuffer.o
OBJFILES     = $(OBJFILESNP:%=../obj/%)
OBJDEPS      = $(OBJFILESNP:%.o=deps/%_deps)

all: ../lib/libDwmCredence.a

../lib/libDwmCredence.a: ${OBJFILES}
	ar rv $@ $^
	-ranlib $@

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

../obj/%.o: %.cc deps/%_deps
	${CXX} ${CXXFLAGS} ${PTHREADCXXFLAGS} ${ALLINC} -c $< -o $@

tarprep: ${TARDIR}/lib/libDwmCredence.a

${TARDIR}/lib/libDwmCredence.a: ../lib/libDwmCredence.a
	${LIBTOOL} --mode=install ../../install-sh -c $< ${TARDIR}/lib/libDwmCredence.a

clean:: clean-tarprep
	rm -f ../lib/libDwmCredence.a ${OBJFILES}

distclean:: clean
	rm -f deps/*_deps

clean-tarprep::
	${LIBTOOL} --mode=clean rm -f ${TARDIR}/lib/libDwmCredence.a

