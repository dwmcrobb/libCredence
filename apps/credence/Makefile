include ../../Makefile.vars

LDFLAGS  = -Wl,-rpath ${DWMDIR}/lib
LTLINK   = ${LIBTOOL} --tag=CXX --mode=link ${CXX}
OBJFILES = credence.o
OBJDEPS	 = $(OBJFILES:%.o=deps/%_deps)
ALLINC   = ${DWMINCS}
ALLINC   += -I../../classes/include -I.
ALLLIBS  = ${DWMLIBS} ${SODIUMLIB}
TARTARGETS  = ${TARDIR}/bin/credence ${TARDIR}/share/man/man1/credence.1
ifeq ("${MANDOC}", "mandoc")
MANHTML = ${MANDOC} -Thtml -Ostyle=../mcplexman.css,man=../html%S/%N.%S.html
TARTARGETS += ${TARDIR}/${HTMLMAN}/html1/credence.1.html
endif

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
 link_cmd="${LTLINK} ${LDFLAGS} -o $(2) $(1) ../../classes/lib/libDwmCredence.la ${ALLLIBS}"; \
 link_cmd_out=`$${link_cmd} 2>&1`; \
 if [ $$? -ne 0 ]; then \
   printf "%s\n%s\n" "$${link_cmd}" "$${link_cmd_out}"; \
   exit 1; \
 fi
endef

#-----------------------------------------------------------------------------

all: credence

credence: credence.o ../../classes/lib/libDwmCredence.la
	$(call Link,$<,$@)

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

../../classes/lib/libDwmCredence.la::
	${MAKE} -s -C ../../classes/src

tarprep: ${TARTARGETS}

${TARDIR}/bin/credence: credence
	${LIBTOOL} --mode=install ../../install-sh -s -c -m 555 $< $@

${TARDIR}/share/man/man1/credence.1: credence.1
	${LIBTOOL} --mode=install ../../install-sh -c -m 644 $< $@

${TARDIR}/${HTMLMAN}/html1/credence.1.html: credence.1
	${MANHTML} $< > $<.html
	../../install-sh -c -m 644 $<.html $@
	rm $<.html

distclean:: clean
	@rm -f ${OBJDEPS}

clean: clean-tarprep
	@${LIBTOOL} --quiet --mode=clean rm -f credence ${OBJFILES}

clean-tarprep::
	@${LIBTOOL} --quiet --mode=uninstall rm -f ${TARTARGETS}
