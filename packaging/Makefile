include ../Makefile.vars

ifeq ("${OSNAME}", "freebsd")
PKGPCDIR = libdata/pkgconfig
else
PKGPCDIR = lib/pkgconfig
endif

TARTARGS = ${TARDIR}/${PKGPCDIR}/libDwmCredence.pc

all::
	echo "nothing to be done for 'all' target."

tarprep: ${TARTARGS}

${TARDIR}/${PKGPCDIR}/libDwmCredence.pc: libDwmCredence.pc
	../install-sh -c -m 444 $< $@

distclean::
	rm -f debcontrol fbsd_manifest libDwmCredence.pc
