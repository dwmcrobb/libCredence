include ../../Makefile.vars

LDFLAGS  = -Wl,-rpath ${DWMDIR}/lib
LTLINK   = ${LIBTOOL} --tag=CXX --mode=link ${CXX}
OBJFILES = credence.o
OBJDEPS	 = $(OBJFILES:%.o=deps/%_deps)
ALLINC   = ${DWMINCS}
ALLINC   += -I../../classes/include -I.
ALLLIBS  = ${DWMLIBS} ${SODIUMLIB}
TARTARGETS  = ${TARDIR}/bin/credence ${TARDIR}/share/man/man1/credence.1

all: credence

credence: credence.o ../../classes/lib/libDwmCredence.la
	${LTLINK} ${LDFLAGS} -o $@ $^ -rpath ${INSTALLPREFIX}/lib ${ALLLIBS}

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

../../classes/lib/libDwmCredence.la::
	${MAKE} -C ../../classes/src

tarprep: ${TARTARGETS}

${TARDIR}/bin/credence: credence
	${LIBTOOL} --mode=install ../../install-sh -s -c -m 555 $< $@

${TARDIR}/share/man/man1/credence.1: credence.1
	${LIBTOOL} --mode=install ../../install-sh -c -m 644 $< $@

clean: clean-tarprep
	${LIBTOOL} --mode=clean rm -f credence ${OBJFILES}

clean-tarprep::
	${LIBTOOL} --mode=uninstall rm -f ${TARTARGETS}
