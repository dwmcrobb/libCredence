include ../../Makefile.vars

LTLINK   = ${LIBTOOL} --tag=CXX --mode=link ${CXX}
OBJFILES = TestChallenge.o \
           TestEd25519KeyPair.o \
           TestKeyStash.o \
           TestKeyType.o \
           TestKnownKeys.o \
           TestKXKeyPair.o \
           TestPeer.o \
           TestShortString.o \
           TestSigner.o \
           TestX25519KeyPair.o \
           TestXChaCha20Poly1305.o \
           TestXChaCha20Streams.o
OBJDEPS	 = $(OBJFILES:%.o=deps/%_deps)
TESTS	 = $(OBJFILES:%.o=%)
CXXFLAGS += -g
LDFLAGS  += -g -Wl,-rpath,${DWMDIR}/lib
ALLINC   = -I../include -I.
ALLINC   += ${DWMINCS}
ALLLIBS  = ${DWMLIBS} ${SODIUMLIB}

all: ${TESTS}

runtests: all
	@ for tp in ${TESTS} ; do \
		printf "%-36s " $$tp ; \
		out=`./$$tp` ; \
		if [ $$? -eq 0 ]; then \
		  printf "%25s\n" "$$out" ; \
		else \
		  printf "\n%s" "$$out" ; \
		fi ; \
	done

#  dependency rule
deps/%_deps: %.cc 
	@echo "making dependencies for $<"
	@set -e; \
	${CXX} -MM ${CXXFLAGS} ${ALLINC} -c $< | \
	 sed 's/\($*\)\.o[ :]*/\1.o $(@D)\/$(@F) : /g' > $@ ; [ -s $@ ] || \
	 rm -f $@

#  only include dependency makefiles if target is not 'clean' or 'distclean'
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
-include ${OBJDEPS}
endif
endif

%.o: %.cc deps/%_deps
	${CXX} ${CXXFLAGS} ${PTHREADCXXFLAGS} ${ALLINC} -c $<

Test%: Test%.o ../lib/libDwmCredence.la
	${LTLINK} ${LDFLAGS} -o $@ $^ ${ALLLIBS}

../lib/libDwmCredence.la::
	${MAKE} -C ../src

clean:
	${LIBTOOL} --mode=clean rm -f ${TESTS} ${OBJFILES}

distclean:: clean
	rm -f deps/*_deps
