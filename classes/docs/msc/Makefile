AuthSequence.pdf: AuthSequence.eps
	epspdf $<

AuthSequence.eps: AuthSequence.msc
	mscgen -Teps -o $@ $<

clean::
	rm -f AuthSequence.eps AuthSequence.pdf

