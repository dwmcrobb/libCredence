include ../../Makefile.vars

LDFLAGS  = -Wl,-rpath ${DWMDIR}/lib
OBJFILES = credence-keygen.o
OBJDEPS	 = $(OBJFILES:%.o=deps/%_deps)
ALLINC   = ${DWMINCS}
ALLINC   += -I../../classes/include -I.
ALLLIBS  = -L../../classes/lib -lDwmCredence ${DWMLIBS} ${SODIUMLIB}
TARTARGETS  = ${TARDIR}/bin/credence-keygen

all: credence-keygen

credence-keygen: credence-keygen.o ../../classes/lib/libDwmCredence.a
	${CXX} ${LDFLAGS} -o $@ $< ${ALLLIBS}

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

../../classes/lib/libDwmCredence.a::
	${MAKE} -C ../../classes/src

tarprep: ${TARTARGETS}

${TARDIR}/bin/credence-keygen: credence-keygen
	../../install-sh -s -c -m 555 $< $@

clean: clean-tarprep
	rm -f credence-keygen ${OBJFILES}

clean-tarprep::
	rm -f ${TARDIR}/bin/credence-keygen
