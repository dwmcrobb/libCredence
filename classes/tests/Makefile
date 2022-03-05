include ../../Makefile.vars

OBJFILES = TestChallenge.o \
           TestKeyStash.o \
           TestKnownKeys.o \
           TestKXKeyPair.o \
           TestSessionClientKeyPair.o \
           TestSessionServerKeyPair.o \
           TestSigner.o \
           TestX25519KeyPair.o \
           TestXChaCha20Poly1305.o \
           TestXChaCha20Streams.o
OBJDEPS	 = $(OBJFILES:%.o=deps/%_deps)
TESTS	 = $(OBJFILES:%.o=%)
CXXFLAGS += -g
LDFLAGS  += -g
ALLINC   = ${DWMINCS}
ALLINC   += -I../include -I.
ALLLIBS  = -L../../classes/lib -lDwmCredence ${DWMLIBS} ${SODIUMLIB}

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

#  only include dependency makefiles if target is not 'clean'
ifneq ($(MAKECMDGOALS),clean)
-include ${OBJDEPS}
endif

%.o: %.cc deps/%_deps
	${CXX} ${CXXFLAGS} ${PTHREADCXXFLAGS} ${ALLINC} -c $<

Test%: Test%.o ../lib/libDwmCredence.a
	${CXX} ${LDFLAGS} -o $@ $< ${ALLLIBS}

../lib/libDwmCredence.a::
	${MAKE} -C ../src

clean:
	${LIBTOOL} --mode=clean rm -f ${TESTS} ${OBJFILES}
