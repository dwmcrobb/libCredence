all:: AuthSequence.pdf AuthSequence.eps AuthSequence2.pdf AuthSequence2.eps
      
%.pdf: %.eps
	epspdf $<

%.eps: %.msc
	mscgen -Teps -o $@ $<

clean::
	rm -f *.eps *.pdf

