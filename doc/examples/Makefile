include ../../Makefile.vars

LDFLAGS  = -Wl,-rpath ${DWMDIR}/lib
LTLINK   = ${LIBTOOL} --tag=CXX --mode=link ${CXX}
SRCFILES = $(shell ls *.cc)
OBJFILES = $(SRCFILES:%.cc=%.o)
EXEFILES = $(SRCFILES:%.cc=%)
OBJDEPS	 = $(OBJFILES:%.o=deps/%_deps)
ALLINC   = ${DWMINCS}
ALLINC   += -I../../classes/include -I.
ALLLIBS  = ${DWMLIBS} ${SODIUMLIB}

all: ${EXEFILES}

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

%: %.o ../../classes/lib/libDwmCredence.la
	${LTLINK} ${LDFLAGS} -o $@ $^ -rpath ${INSTALLPREFIX}/lib ${ALLLIBS}

../../classes/lib/libDwmCredence.la::
	${MAKE} -C ../../classes/src

clean::
	${LIBTOOL} --mode=clean rm -f ${EXEFILES} ${OBJFILES}

