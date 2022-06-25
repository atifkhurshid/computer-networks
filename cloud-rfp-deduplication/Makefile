default: all

all: build

build:
	javac -cp .:./lib/* MyDedup.java

upload:
	java -cp .:./lib/* MyDedup upload 512 2048 65535 257 MyDedup.class azure

download:
	java -cp .:./lib/* MyDedup download MyDedup.class MYDedupDownloaded.class azure

delete:
	java -cp .:./lib/* MyDedup delete MyDedup.class azure

clean:
	rm *.class
