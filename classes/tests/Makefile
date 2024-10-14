include ../../Makefile.vars

LTLINK   = ${LIBTOOL} --quiet --tag=CXX --mode=link ${CXX}
OBJFILES = $(addsuffix .o,$(basename $(shell ls *.cc)))
OBJDEPS	 = $(OBJFILES:%.o=deps/%_deps)
TESTS	 = $(OBJFILES:%.o=%)
CXXFLAGS += -g
LDFLAGS  += -g -Wl,-rpath,${DWMDIR}/lib
ALLINC   = -I../include -I.
ALLINC   += ${DWMINCS}
ALLLIBS  = ${DWMLIBS} ${SODIUMLIB}

#-----------------------------------------------------------------------------
define Compile
 @echo compiling $(1) ; \
 cxx_cmd="${CXX} ${CXXFLAGS} ${PTHREADCXXFLAGS} ${ALLINC} -c $(1)"; \
 cxx_cmd_out=`$${cxx_cmd} 2>&1`; \
 if [ $$? -ne 0 ]; then \
   printf "%s\n%s\n" "$${cxx_cmd}" "$${cxx_cmd_out}"; \
   exit 1; \
 fi
endef

#-----------------------------------------------------------------------------
define Link
 @echo linking $(2) ; \
 link_cmd="${LTLINK} ${LDFLAGS} -o $(2) $(1) ../lib/libDwmCredence.la ${ALLLIBS}"; \
 link_cmd_out=`$${link_cmd} 2>&1`; \
 if [ $$? -ne 0 ]; then \
   printf "%s\n%s\n" "$${link_cmd}" "$${link_cmd_out}"; \
   exit 1; \
 fi
endef

#-----------------------------------------------------------------------------

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
	$(call Compile,$<)

Test%: Test%.o ../lib/libDwmCredence.la
	$(call Link,$<,$@)

../lib/libDwmCredence.la::
	${MAKE} -s -C ../src

clean::
	@${LIBTOOL} --quiet --mode=clean rm -f ${TESTS} ${OBJFILES}

distclean:: clean
	@rm -f deps/*_deps
