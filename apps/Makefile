APPS       = credence
APPLSCLEAN = $(APPS:%=%-clean)
TARPREP    = $(APPS:%=%-tarprep)

all:: ${APPS}

${APPS}::
	${MAKE} -C $@

tarprep:: ${TARPREP}
${TARPREP}::
	${MAKE} -C $(patsubst %-tarprep,%,$@) tarprep

clean:: ${APPSCLEAN}
${APPSCLEAN}::
	${MAKE} -C $(patsubst %-clean,%,$@) clean
