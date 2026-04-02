CC = gcc
CFLAGS = -fno-stack-protector -z execstack -no-pie -g

all: vuln-cgi

vuln-cgi: vuln-cgi.c
	$(CC) $(CFLAGS) -o vuln-cgi vuln-cgi.c

clean:
	rm -f vuln-cgi

install: vuln-cgi
	mkdir -p /var/www/cgi-bin
	cp vuln-cgi /var/www/cgi-bin/
	chmod +x /var/www/cgi-bin/vuln-cgi
	@echo "Installed to /var/www/cgi-bin/vuln-cgi"
