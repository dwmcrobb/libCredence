include ../../Makefile.vars

COMPILE  = ${CXX}
DEPSDIR  = deps
OBJDIR   = .
OBJFILES = $(addsuffix .o,$(basename $(shell ls *.cc)))
OBJDEPS	 = $(OBJFILES:%.o=${DEPSDIR}/%_deps)
TESTS	 = $(OBJFILES:%.o=%)
CXXFLAGS += -g
LDFLAGS  += -g -Wl,-rpath,${DWMDIR}/lib
ALLINC   = -I../include -I. ${DWMINCS}
ALLLIBS  = ${DWMLIBS} ${SODIUMLIB}

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

#  dependencies
$(eval $(call MakeDep,${OBJDIR}))

#  object files
${OBJDIR}/%.o: %.cc ${DEPSDIR}/%_deps
	$(call Compile,$<,$@)

#  executables
Test%: ${OBJDIR}/Test%.o ../lib/libDwmCredence.la
	$(call Link,$<,$@)

../lib/libDwmCredence.la::
	${MAKE} -s -C ../src

clean::
	@${LTCLEAN} ${TESTS} ${OBJFILES}

distclean:: clean
	@rm -f deps/*_deps
