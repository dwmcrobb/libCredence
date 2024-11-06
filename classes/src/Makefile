load $(shell pkg-config --variable=libdir dwmgmk)/dwm_gmk.so(dwm_gmk_setup)
$(dwm_aliasfn my,dwm_my)
$(dwm_myns lib)
$(my mydir := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))))

$(dwm_include $(abspath $(my mydir)/../../Makefile.vars))

$(dwm_setltlibvars lib,../lib/libDwmCredence.la,../obj,deps,.+\.(cc|lex|y)$$)

$(my CxxFlags   := ${CXXFLAGS} ${CLASSINC} ${DWMINCS})
$(my Compile    := ${LTCOMPILE} $(my CxxFlags))
$(my Link       := ${LTLINK})
$(my LinkRpath  := -rpath ${INSTALLPREFIX}/lib)
$(my LibVersion := -version-info ${SHLIB_VERSION})
$(my ExtLibs    := ${DWMLIBSONLY} ${SODIUMLIB})
$(my LinkFlags  := $(my LinkRpath) $(my LibVersion) ${LDFLAGS} $(my ExtLibs))

$(eval TARGETS          $(dwm_ifcwd :=,+=) $(my lib.Lib))
$(eval DEPSTARGETS      $(dwm_ifcwd :=,+=) $(my lib.Deps))
$(eval CLEANTARGETS     $(dwm_ifcwd :=,+=) $(my lib.Clean))
$(eval LTCLEANTARGETS   $(dwm_ifcwd :=,+=) $(my lib.LtClean))
$(eval DISTCLEANTARGETS $(dwm_ifcwd :=,+=) $(my lib.Deps))
$(eval TARTARGETS       $(dwm_ifcwd :=,+=) ${TARDIR}/lib/libDwmCredence.la)

#-----------------------------------------------------------------------------

# .SECONDARY: $(my FlexOuts) $(my BisonOuts)

$(my lib.Lib):: $(my lib.SharedObjs)
	@dwmgmk_quiet "creating $(dwm_relpwd $@)" \
	 $(my lib.Link) -o $@ $(my lib.SharedObjs) $(my lib.LinkFlags)

#  generate dependency rule
$(eval $(dwm_cppdeps $(my lib.DepsDir),$(my lib.ObjDir),\
$(my lib.mydir)/%.cc,${CXX} -MM $(my CxxFlags) -c $<,.o .lo))

$(my lib.ObjDir)/%.lo: $(my lib.mydir)/%.cc $(my lib.DepsDir)/%_deps
	@dwmgmk_quiet "compiling $(dwm_relpwd $<)" \
	 $(my lib.Compile) -c $< -o $@

#  only include dependency makefiles if target is not 'clean' or 'distclean'
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
$(dwm_include $(my lib.Deps))
endif
endif

$(my lib.mydir)/%Parse.cc $(my lib.mydir)/%Parse.hh &: $(my lib.mydir)/%Parse.y
	@dwmgmk_quiet "generating parser from $(dwm_relpwd $<)" \
	 bison -d -o $(patsubst %.hh,%.cc,$@) $<

$(my lib.mydir)/%Lex.cc: $(my lib.mydir)/%Lex.lex
	@dwmgmk_quiet "generating lexer from $(dwm_relpwd $<)" \
	 flex -o$@ $<

${TARDIR}/lib/libDwmCredence.la: $(my lib.Lib)
	${INSTALL} -c $< $@

$(dwm_include $(abspath $(my lib.mydir)/../../Makefile.rules))
