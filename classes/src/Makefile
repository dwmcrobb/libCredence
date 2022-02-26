include ../../Makefile.vars

ALLINC       = -I../include ${DWMINCS}
OBJFILESNP   = DwmCredenceEd25519KeyPair.o \
               DwmCredenceKeyStash.o \
               DwmCredenceSigner.o \
               DwmCredenceUtils.o
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

clean::
	rm -f ../lib/libDwmCredence.a ${OBJFILES}

distclean:: clean
	rm -f deps/*_deps
