include ../Makefile.vars

HTMLDOCINSTALLDIR = ${TARDIR}/share/doc/libDwmCredence

.PHONY : clean clean-install clean-tarprep install tarprep uninstall

html/index.html: ../classes/include/*.hh examples/*.cc doxygenDocs.css
	-doxygen Doxyfile
	cp mcplex_net_blue_shadowed.svg html

www: html/index.html
	tar --exclude=\*.md5 -zcvf html.tgz html

tarprep: ${HTMLDOCINSTALLDIR}/index.html
	mkdir -p ${TARDIR}/share/doc/libDwmCredence
	find html -name \*.md5 -exec rm {} \;
	cp html/* ${TARDIR}/share/doc/libDwmCredence

install: ${DOCINSTALLDIR}/index.html

${HTMLDOCINSTALLDIR}/index.html: html/index.html
	mkdir -p ${HTMLDOCINSTALLDIR}
	cp html/* ${HTMLDOCINSTALLDIR}
	find ${HTMLDOCINSTALLDIR} -name \*.md5 -exec rm {} \;

uninstall: clean-install

clean:: clean-tarprep
	rm -Rf html latex man

clean-install::
	rm -Rf ${HTMLDOCINSTALLDIR}

clean-tarprep::
	rm -Rf ${HTMLDOCINSTALLDIR}

distclean::
	rm -f Doxyfile
