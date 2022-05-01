include ../Makefile.vars

HTMLDOCINSTALLDIR = ${TARDIR}/share/doc/libDwmCredence
MANPAGES          = $(shell find man -type f \! -name \*\\.hh\\.3)
INSTMANPAGES      = $(MANPAGES:%=${TARDIR}/share/%)

.PHONY : clean clean-install clean-tarprep install tarprep uninstall

html/index.html: ../classes/include/*.hh examples/*.cc doxygenDocs.css
	-doxygen Doxyfile
	cp mcplex_net_blue_shadowed.svg html

www: html/index.html
	tar --exclude=\*.md5 -zcvf html.tgz html

tarprep: ${HTMLDOCINSTALLDIR}/index.html ${INSTMANPAGES}

${HTMLDOCINSTALLDIR}/index.html: html/index.html
	mkdir -p ${HTMLDOCINSTALLDIR}
	cp html/* ${HTMLDOCINSTALLDIR}
	find ${HTMLDOCINSTALLDIR} -name \*.md5 -exec rm {} \;

${TARDIR}/share/man/man3/%.3: man/man3/%.3
	../install-sh -c -m 644 $< $@

clean:: clean-tarprep
	rm -Rf html latex man

clean-tarprep::
	rm -Rf ${HTMLDOCINSTALLDIR} ${INSTMANPAGES}

distclean::
	rm -f Doxyfile
