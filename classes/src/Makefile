include ../../Makefile.vars

ALLINC      := -I../include ${DWMINCS}
COMPILE     := ${LTCOMPILE}
DEPSDIR     := deps
LTINSTALL   := ${LIBTOOL} --mode=install ../../install-sh
LTUNINSTALL := ${LIBTOOL} --quiet --mode=uninstall rm -f
OBJDIR      := ../obj
OBJFILESNP  := $(call Unique,$(addsuffix .o,$(basename $(shell ls *.cc *.lex *.y))))
OBJFILES        := $(OBJFILESNP:%=${OBJDIR}/%)
SHARED_OBJFILES := $(OBJFILES:%.o=%.lo)
OBJDEPS         := $(OBJFILESNP:%.o=${DEPSDIR}/%_deps)
shlib_version   := $(shell ../../getvers.sh -s)

#-----------------------------------------------------------------------------
define LinkLibraries
 @printf "creating %s ..." $(notdir $(1))
 @link_cmd="${LTLINK} -o $(1) ${SHARED_OBJFILES} -rpath ${INSTALLPREFIX}/lib -version-info ${shlib_version} ${LDFLAGS} ${DWMLIBSONLY} ${SODIUMLIB}"; \
 link_cmd_out=`$${link_cmd} 2>&1`; \
 if [ $$? -ne 0 ]; then \
   printf "%s\n%s\n" "$${link_cmd}" "$${link_cmd_out}"; \
   exit 1; \
 fi ; \
 printf " done\n"
endef

#-----------------------------------------------------------------------------

all: ../lib/libDwmCredence.la

../lib/libDwmCredence.la: ${SHARED_OBJFILES}
	$(call LinkLibraries,$@)

#  dependencies
$(eval $(call MakeDep,${OBJDIR}))

${OBJDIR}/%.lo ${OBJDIR}/%.o: %.cc ${DEPSDIR}/%_deps
	$(call Compile,$<,$@)

DwmCredenceServerConfigLex.cc: DwmCredenceServerConfigLex.lex DwmCredenceServerConfigParse.hh
	flex -o$@ $<

DwmCredenceServerConfigParse.hh: DwmCredenceServerConfigParse.cc

DwmCredenceServerConfigParse.cc: DwmCredenceServerConfigParse.y
	bison -d -o$@ $<

tarprep: ${TARDIR}/lib/libDwmCredence.la

${TARDIR}/lib/libDwmCredence.la: ../lib/libDwmCredence.la
	${LTINSTALL} -c $< ${TARDIR}/lib/libDwmCredence.la

clean:: clean-tarprep
	@${LTCLEAN} ../lib/libDwmCredence.la ${SHARED_OBJFILES}
	@${LTCLEAN} DwmCredenceServerConfigParse.hh \
	  DwmCredenceServerConfigParse.cc DwmCredenceServerConfigLex.cc

distclean:: clean
	@rm -f ${DEPSDIR}/*_deps

clean-tarprep::
	@${LTUNINSTALL} ${TARDIR}/lib/libDwmCredence.la

