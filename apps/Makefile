APPS       = credence
APPSCLEAN  = $(APPS:%=%-clean)
TARPREP    = $(APPS:%=%-tarprep)
DISTCLEAN  = $(APPS:%=%-distclean)

all:: ${APPS}

${APPS}::
	${MAKE} -C $@

tarprep:: ${TARPREP}
${TARPREP}::
	${MAKE} -C $(patsubst %-tarprep,%,$@) tarprep

clean:: ${APPSCLEAN}
${APPSCLEAN}::
	${MAKE} -C $(patsubst %-clean,%,$@) clean

distclean:: ${DISTCLEAN}
${DISTCLEAN}::
	${MAKE} -C $(patsubst %-distclean,%,$@) distclean
