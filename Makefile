# Make file for open-crypto - popen-source GCM crypto and api routines

all:
	mkdir -p build
	cp /opt/crypto/lib/gcm/gcm.o build
	cp /opt/crypto/lib/gcm/aes.o build
	(cd src; make package)

clean:
	(cd src; make clean)
	(cd package; make clean)
	rm -rf build opt *.deb

package:	all
	(cd package; make package)


