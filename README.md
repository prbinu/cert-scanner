# cert-scanner
A fast TLS Cert scanner written in golang to scan HTTPS and SMTP servers, extract certificate information, and print it in a machine readable format.

### Installation

Prequisites: [golang](https://golang.org/dl/)

```
% git clone https://github.com/prbinu/cert-scanner.git
% cd cert-scanner
% go build
```

To test:
```
% echo "yahoo.com" | ./cert-scanner -port 443 --quiet
```

###Usage
```
% cert-scanner --help

Usage of ./cert-scanner:
  -CAfile string
    	PEM format file of CA's
  -batch-size int
    	flag to process requests in batch (default 32)
  -delimiter string
    	field separator char, works with -line option only (default "|")
  -fields string
    	field names to display (eg 'ip, host, pubkey_alg')
  -filter string
    	query filter to remove unwanted output (eg 'pubkey_alg = "SHA" AND x509_ver = 3')
  -json
    	JSON output
  -mx-lookup
    	resolve MX record (for -starttls smtp)
  -output-dir string
    	output directory to save output files (default ".")
  -port string
    	Port to scan (default "25")
  -pretty
    	formatted JSON output
  -quiet
    	supress output to stdout
  -starttls string
    	use the STARTTLS command before starting TLS for those protocols that support it, where 'prot' defines which one to assume.  Currently, only 'smtp' is supported.
  -timeout int
    	per-request timeout (default 10)
  -tls-version string
    	protocol version to use {ssl3, tls1, tls1_1, tls1_2} (def all versions)

```

###Caveats
Since the Go TLS implementation does not support deprecated/insecure ciphers and old SSL versions, cert-scanner does not have weak cipher test or enumeration feature.
