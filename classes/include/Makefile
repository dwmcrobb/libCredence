load $(shell pkg-config --variable=libdir dwmgmk)/dwm_gmk.so(dwm_gmk_setup)
libIncDir := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

$(dwm_include $(abspath $(libIncDir)/../../Makefile.vars))

libIncHdrNames    := $(dwm_files $(libIncDir),.+\.hh)
libIncHdrs        := $(libIncHdrNames:%.hh=$(libIncDir)/%.hh)
libIncTarPrepHdrs := $(libIncHdrNames:%=${TARDIR}/include/libDwmCredence/%)

$(eval TARTARGETS       $(dwm_ifcwd :=,+=) $(libIncTarPrepHdrs))
$(eval DISTCLEANTARGETS $(dwm_ifcwd :=,+=) $(libIncTarPrepHdrs))

${TARDIR}/include/libDwmCredence/%.hh: $(libIncDir)/%.hh
	${INSTALL} -c -m 444 $< $@

$(dwm_include $(abspath $(libIncDir)/../../Makefile.rules))
