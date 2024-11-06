load $(shell pkg-config --variable=libdir dwmgmk)/dwm_gmk.so(dwm_gmk_setup)
myfile := $(abspath $(lastword $(MAKEFILE_LIST)))
$(dwm_myns credence)
$(dwm_aliasfn my,dwm_my)
$(dwm_aliasfn ifcwd,dwm_ifcwd)
$(my mydir := $(abspath $(dir $(myfile))))

$(dwm_include_once $(abspath $(my mydir)/../../classes/src/Makefile))

$(my CxxFlags   := ${CXXFLAGS} ${CLASSINC} ${DWMINCS})
$(my Libs       := ${DWWLIBS} ${SODIUMLIB})
$(my Compile    := ${CXX} $(my CxxFlags))
$(my Link       := ${LTLINK})
$(my LdFlags    := ${LDFLAGS} -g -Wl,-rpath,${DWMDIR}/lib)
$(my Srcs       := $(dwm_files $(my mydir),.+\.cc))
$(my ObjNames   := $(subst .cc,.o,$(my Srcs)))
$(my ObjDir     := $(my mydir))
$(my DepsDir    := $(my mydir)/deps)
$(my Objs       := $(patsubst %,$(my ObjDir)/%,$(my ObjNames)))
$(my ObjDeps    := $(patsubst %.o,$(my DepsDir)/%_deps,$(my ObjNames)))
$(my Exes       := $(patsubst %.o,%,$(my Objs)))
$(my Clean      := $(my credence.Objs))
$(my LtClean    := $(my credence.Exes))
$(my TarTargets := ${TARDIR}/bin/credence ${TARDIR}/share/man/man1/credence.1)

$(eval TARGETS          $(ifcwd :=,+=) $(my credence.Exes))
$(eval DEPSTARGETS      $(ifcwd :=,+=) $(my credence.ObjDeps))
$(eval CLEANTARGETS     $(ifcwd :=,+=) $(my credence.Clean))
$(eval LTCLEANTARGETS   $(ifcwd :=,+=) $(my credence.LtClean))
$(eval DISTCLEANTARGETS $(ifcwd :=,+=) $(my credence.ObjDeps))
$(eval TARTARGETS       $(ifcwd :=,+=) $(my credence.TarTargets))

$(dwm_include $(abspath $(my mydir)/../../Makefile.rules))

ifeq ("${MANDOC}", "mandoc")
MANHTML = ${MANDOC} -Thtml -Ostyle=../mcplexman.css,man=../html%S/%N.%S.html
TARTARGETS += ${TARDIR}/${HTMLMAN}/html1/credence.1.html
endif

#  generate dependency rule
$(eval $(dwm_cppdeps $(my credence.mydir)/deps,(my credence.mydir),\
$(my credence.mydir)/%.cc,${CXX} -MM $(my credence.CxxFlags) -c $<))

#  only include dependency makefiles if target is not a 'clean' target
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
$(dwm_include $(my credence.ObjDeps))
endif
endif

#-----------------------------------------------------------------------------

$(my mydir)/credence:: $(my Objs) ${CLASSLIB}
	@dwmgmk_quiet "linking $(dwm_relpwd $@)" \
	 $(my credence.Link) $(my credence.LdFlags) -o $@ $^ \
	 $(my credence.Libs)

$(my credence.mydir)/%.o: $(my mydir)/%.cc $(my DepsDir)/%_deps
	@dwmgmk_quiet "compiling $(dwm_relpwd $<)" \
	 $(my credence.Compile) -c $< -o $@

${TARDIR}/bin/credence: $(my mydir)/credence
	${INSTALL} -s -c -m 555 $< $@

${TARDIR}/share/man/man1/credence.1: $(my mydir)/credence.1
	${INSTALL} -c -m 644 $< $@

${TARDIR}/${HTMLMAN}/html1/credence.1.html: $(my mydir)/credence.1
	${MANHTML} $< > $<.html
	${INSTALL} -c -m 644 $<.html $@
	rm $<.html

