// Copyright (c) 2016, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const loggerCount = 2

var loggers = make([]*Logger, loggerCount)

// Output formatter interface (-json, -delimiter, -pretty flags)
type Formatter interface {
	Do(map[string]interface{}) ([]byte, error)
}

// Convert output to JSON format
type JSONFormatter struct {
	pretty bool
}

// Convert output to JSON format
func (jf *JSONFormatter) Do(tlsrec map[string]interface{}) ([]byte, error) {
	if jf.pretty {
		return json.MarshalIndent(tlsrec, "", "  ")
	} else {
		return json.Marshal(tlsrec)
	}
}

// Convert output to key:value format, delimited by '|' or -delimiter flag value
type KVFormatter struct {
	pretty    bool
	delimiter string
}

// Convert output to key:value format, delimited by '|' or -delimiter flag value
func (kv *KVFormatter) Do(tlsrec map[string]interface{}) ([]byte, error) {

	var output string
	for k, v := range tlsrec {
		if kv.pretty {
			output += fmt.Sprintf("%s: %v\n", k, v)
		} else {
			output += fmt.Sprintf("%s: %v%s", k, v, kv.delimiter)
		}
	}

	if kv.pretty {
		output = strings.TrimSuffix(output, "\n")
	} else {
		output = strings.TrimSuffix(output, kv.delimiter)
	}
	//fmt.Printf(output)

	return []byte(output), nil
}

// Field filter - Used to whitelist fields you wanted to output (-fields flag)
type FieldFilter struct {
	tlsrec map[string]interface{}
}

// Initialize FieldFilter with whitelisted fields
func FieldFilterInit(fields string) (*FieldFilter, error) {
	f := strings.Split(fields, ",")
	// remove extra whitespaces
	f = DeleteEmpty(f)
	ff := new(FieldFilter)
	ff.tlsrec = make(map[string]interface{})
	flen := len(f)

	for i := 0; i < flen; i++ {
		// value will be added later (see next function)
		ff.tlsrec[f[i]] = ""
		//fmt.Println("Field: ", f[i])
	}
	return ff, nil

}

func (ff *FieldFilter) Run(tlsrec map[string]interface{}) map[string]interface{} {

	for k, _ := range ff.tlsrec {
		ff.tlsrec[k] = tlsrec[k]
	}
	return ff.tlsrec
}

// Validate and convert the -filter value to respective type
func TypeConvertor(value string, typ string) (interface{}, error) {
	switch typ {
	case "string":
		return value, nil

	case "int":
		if v2, err := strconv.Atoi(value); err == nil {
			return v2, nil
		} else {
			return nil, errors.New("Invalid value: " + value + "of type int")
		}

	case "time.Time":
		const shortForm = "2006-Jan-02"
		//if v2, err := time.Parse(time.RFC3339, value); err == nil {
		if v2, err := time.Parse(shortForm, value); err == nil {
			return v2.Unix(), nil
		} else {
			return nil, errors.New("Invalid value: " + value + "of type date/time (format: YYYY-MMM-DD eg 2015-Jan-12")
		}

	case "bool":
		if v2, err := strconv.ParseBool(value); err == nil {
			return v2, nil
		} else {
			return nil, errors.New("Invalid value: " + value + "of type bool (use true OR false")
		}
	}

	return nil, errors.New("Invalid/Unknown type of " + typ + " value: " + value)

}

// Expression evaluator (-filter flag)
type LogicalExpr struct {
	// store expressions in triplets ({e1, op, e2}, {e3, op, e4}, ...)
	exprns []Expr
	// binding logical operator (AND, OR, OR, ...)
	lop []string
}

// Initialize query fitler expression passed in -filter flag
func LogicalExprInit(exp string) (*LogicalExpr, error) {
	s := strings.Split(exp, " ")
	// remove extra whitespaces
	s = DeleteEmpty(s)
	le := new(LogicalExpr)
	toklen := len(s)
	var err error

	// process the splice in triplets
	for i := 0; i < toklen; {
		var expr Expr
		var typ string
		var ok bool

		// [1] field name
		if typ, ok = keyType[s[i]]; !ok {
			return nil, errors.New("Invalid field: " + s[i])
		}
		// store field name
		expr.key = s[i]

		i++
		if i >= toklen {
			return nil, errors.New("errors")
		}

		// [2] Operator
		if _, ok = validOperators[s[i]]; !ok {
			op := "{ "
			for o := range validOperators {
				op += o + " "
			}
			op += "}"
			return nil, errors.New("Invalid operator: " + s[i] + " Valid operators: " + op)
		}
		// store operator
		expr.op = s[i]

		i++
		if i >= toklen {
			return nil, errors.New("errors")
		}

		// [3] field value
		if expr.value, err = TypeConvertor(s[i], typ); err != nil {
			return nil, err
		}

		// add the expr triplet to le.exprns
		le.exprns = append(le.exprns, expr)

		i++
		if i < toklen {
			// add logical operator (AND, OR)
			le.lop = append(le.lop, s[i])
			i++
		}
	}

	// TODO debug statements; remove these later
	/*for _, e := range le.exprns {
		fmt.Printf("key:%s\t Val: %s\t Op: %s\n", e.key, e.value, e.op)
	}
	for _, l := range le.lop {
		fmt.Printf("LOP: %s\n", l)
	}*/
	return le, nil
}

// Evaluate the expression against a tls stats record
func (le *LogicalExpr) Eval(tlsrec map[string]interface{}) bool {
	var eo []bool
	for _, e := range le.exprns {
		eo = append(eo, e.Eval(tlsrec))
	}

	j := 0
	ret := eo[0]
	for i := 1; i < len(eo); {
		switch le.lop[j] {
		case "AND":
			ret = (ret && eo[i])
		case "OR":
			ret = (ret || eo[i])

		}
		i += 2
		j += 1
	}

	return ret
}

// Expression triplet
type Expr struct {
	key   string
	value interface{}
	op    string
}

// eval expression e against matching tlsrec field
func (e *Expr) Eval(tlsrec map[string]interface{}) bool {
	if v, ok := tlsrec[e.key]; ok {
		switch keyType[e.key] {
		case "string":
			return e.evalStr(v)
		case "int":
			return e.evalInt(v)
		case "time.Time":
			return e.evalTime(v)
		case "bool":
			return e.evalBool(v)
		}
	}
	return false
}

func (e *Expr) evalBool(v1 interface{}) bool {
	v, _ := v1.(bool)
	value, _ := e.value.(bool)

	switch e.op {
	case "=":
		return (v == value)
	case "!=":
		return (v != value)

	}
	return false
}

func (e *Expr) evalTime(v1 interface{}) bool {
	value, _ := e.value.(int64)
	v2, _ := v1.(time.Time)
	v := v2.Unix()

	switch e.op {
	case "=":
		return (v == value)
	case "!=":
		return (v == value)
	case ">":
		return (v > value)
	case ">=":
		return (v >= value)
	case "<":
		return (v < value)
	case "<=":
		return (v <= value)
	}
	return false
}

func (e *Expr) evalInt(v1 interface{}) bool {

	value, _ := e.value.(int)
	v, _ := v1.(int)

	switch e.op {
	case "=":
		return (v == value)
	case "!=":
		return (v == value)
	case ">":
		return (v > value)
	case ">=":
		return (v >= value)
	case "<":
		return (v < value)
	case "<=":
		return (v <= value)
	}
	return false
}

func (e *Expr) evalStr(v interface{}) bool {
	switch e.op {
	case "=":
		return (v == e.value)
	case "!=":
		return (v == e.value)
	case "LIKE":
		// Compile the expression once, usually at init time.
		// Use raw strings to avoid having to quote the backslashes.
		//var validID = regexp.MustCompile(`^[a-z]+\[[0-9]+\]$`)
		value, _ := e.value.(string)
		v1, _ := v.(string)
		var regval = regexp.MustCompile(value)
		return regval.MatchString(v1)
	}
	return false
}

// remove empty entries in the slice
func DeleteEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

var tlsVersion = map[string]uint16{
	"ssl3":   tls.VersionSSL30, // not supported by Go TLS client :-(
	"tls1":   tls.VersionTLS10,
	"tls1_1": tls.VersionTLS11,
	"tls1_2": tls.VersionTLS12,
}

// Scanner struct - maintains per-request state
type Scanner struct {
	port      string
	mxLookup  bool
	pretty    bool
	delimiter string
	starttls  string
	fmt       Formatter
	filter    string
	exp       *LogicalExpr
	ff        *FieldFilter
	record    chan []byte
	errRecord chan []byte
	host      chan string
	timeout   time.Duration
	wg        *sync.WaitGroup
	certPool  *x509.CertPool
	tlsConfig *tls.Config
	quiet     bool
}

// Starting point!
func main() {
	portPtr := flag.String("port", "25", "Port to scan")
	mxLookupPtr := flag.Bool("mx-lookup", false, "resolve MX record (for -starttls smtp)")
	fdelimiterPtr := flag.String("delimiter", "|", "field separator char, works with -line option only")
	outputDirPtr := flag.String("output-dir", ".", "output directory to save output files")
	prettyPtr := flag.Bool("pretty", false, "formatted JSON output")
	jsonPtr := flag.Bool("json", false, "JSON output")
	timeoutPtr := flag.Int("timeout", 10, "per-request timeout")
	batchCntPtr := flag.Int("batch-size", 32, "flag to process requests in batch")
	starttlsPtr := flag.String("starttls", "", "use the STARTTLS command before starting TLS for those protocols that support it, where 'prot' defines which one to assume.  Currently, only 'smtp' is supported.")
	filterPtr := flag.String("filter", "", "query filter to remove unwanted output (eg 'pubkey_alg = \"SHA\" AND x509_ver = 3')")
	fieldsPtr := flag.String("fields", "", "field names to display (eg 'ip, host, pubkey_alg')")
	CAfilePtr := flag.String("CAfile", "", "PEM format file of CA's")
	tlsVerPtr := flag.String("tls-version", "", "protocol version to use {ssl3, tls1, tls1_1, tls1_2} (def all versions)")
	quietPtr := flag.Bool("quiet", false, "supress output to stdout")
	flag.Parse()
	//flag.PrintDefaults()

	dl := *fdelimiterPtr
	if *prettyPtr == true {
		dl = "\n"
	}

	var logDone = make(chan bool, 2)
	var record = make(chan []byte, *batchCntPtr)
	loggers[0] = NewLogger(*outputDirPtr+"/tls-certs.txt", logDone)
	// goroutine to log messages to file
	go loggers[0].Process(record)

	var errRecord = make(chan []byte)
	loggers[1] = NewLogger(*outputDirPtr+"/scan-errors.txt", logDone)
	// goroutine to log error messages to file
	go loggers[1].Process(errRecord)

	// process -json / -pretty / -delimiter flags
	var fmtr Formatter
	if *jsonPtr {
		fmtr = &JSONFormatter{*prettyPtr}
	} else {
		fmtr = &KVFormatter{*prettyPtr, *fdelimiterPtr}
	}

	// process -filter flag
	var le *LogicalExpr
	var err error
	if len(*filterPtr) > 0 {
		if le, err = LogicalExprInit(*filterPtr); err != nil {
			fmt.Println(err)
			os.Exit(1)
			return
		}
	}

	// load CA certs -CAfile flag
	var certPool *x509.CertPool
	if len(*CAfilePtr) > 0 {
		cp, err := CACerts(*CAfilePtr)
		if err == nil {
			certPool = cp
		} // else use default CA; TODO but do we need to log it?
	}

	// tls version
	var tlsConfig *tls.Config
	if len(*tlsVerPtr) > 0 {
		ver, ok := tlsVersion[*tlsVerPtr]

		if !ok {
			fmt.Println("Invalid tls-version: " + *tlsVerPtr)
			os.Exit(1)
			return
		}

		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         ver,
			MaxVersion:         ver,
		}

	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	//var host = make(chan string, *batchCntPtr)
	var host = make(chan string)
	var wg sync.WaitGroup
	// create and init per-request scanner object
	for i := 0; i < *batchCntPtr; i++ {
		var ff *FieldFilter

		// process -field flag
		if len(*fieldsPtr) > 0 {
			ff, _ = FieldFilterInit(*fieldsPtr)
		}

		s := Scanner{
			port:      *portPtr,
			mxLookup:  *mxLookupPtr,
			pretty:    *prettyPtr,
			delimiter: dl,
			starttls:  *starttlsPtr,
			fmt:       fmtr,
			filter:    *filterPtr,
			exp:       le,
			ff:        ff,
			record:    record,
			errRecord: errRecord,
			host:      host,
			timeout:   time.Duration(*timeoutPtr) * time.Second,
			wg:        &wg,
			certPool:  certPool,
			tlsConfig: tlsConfig,
			quiet:     *quietPtr,
		}

		go s.Run()
	}

	wg.Add(*batchCntPtr)

	scanner := bufio.NewScanner(os.Stdin)
	var count int
	for scanner.Scan() {
		count++
		log.Printf("[%v] <<< %s\n", count, scanner.Text())
		host <- scanner.Text()
	}

	// close host channel to signal no more hosts to scan
	close(host)
	log.Println("waiting to close...")
	// wait for scanners to complete
	wg.Wait()
	// closing loggers
	close(record)
	close(errRecord)

	done := make(chan bool, 1)
	go func() {
		<-logDone
		<-logDone
		close(done)
	}()

	// wait for logger to flush and exit the goroutines
	select {
	case <-done:
		// use err and reply
	case <-time.After(time.Second * time.Duration(*timeoutPtr+10)):
		// call timed out
		log.Println("main TIMEOUT")
	}

	log.Println("done!")
}

// Scan the endpoint
func (s Scanner) Run() {
	defer s.wg.Done()

	for addr := range s.host {
		c3 := make(chan error, 1)
		if len(s.starttls) == 0 {
			go func() { c3 <- s.TlsConnect(addr) }()
		} else {
			go func() { c3 <- s.StarttlsConnect(addr) }()
		}

		<-c3
	}

	//log.Println("run-done")
}

// Scan endpoints like HTTPS
func (s Scanner) TlsConnect(addr string) error {

	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	c, err := tls.DialWithDialer(dialer, "tcp", addr+":"+s.port, s.tlsConfig)
	if err != nil {
		errmsg := fmt.Sprintf("host: %s| error: connect failed| error_msg: %v\n", addr, err)
		s.errRecord <- []byte(errmsg)
		return err
	}

	defer c.Close()
	var tlsrec = make(map[string]interface{})
	state := c.ConnectionState()

	tlsrec["host"] = addr
	a, _ := c.RemoteAddr().(*net.TCPAddr)
	tlsrec["ip"] = a.IP
	s.ParsePeerX509Certs(addr, &state, tlsrec)
	s.LogMsg(tlsrec)
	return c.Close()
}

func (s Scanner) StarttlsConnect(addr string) error {

	var errmsg string
	if s.mxLookup {
		mxs, err := net.LookupMX(addr)
		if err != nil {
			errmsg := fmt.Sprintf("host: %s| error: MX lookup FAILED| error_msg: %v\n", addr, err)
			s.errRecord <- []byte(errmsg)
			return err
		}

		if len(mxs) > 0 {
			addr = mxs[0].Host
		} else {
			errmsg := fmt.Sprintf("host: %s| error: Empty MX lookup| error_msg: %v\n", addr, err)
			s.errRecord <- []byte(errmsg)
			return err
		}
	}

	conn, err := net.DialTimeout("tcp", addr+":"+s.port, s.timeout)
	if err != nil {
		errmsg := fmt.Sprintf("host: %s| error: connect failed| error_msg: %v\n", addr, err)
		s.errRecord <- []byte(errmsg)
		return err
	}

	if err = conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		//errmsg := fmt.Sprintf("host: %s| error: connect setDeadline failed| error_msg: %v\n", addr, err)
		//s.errRecord <- []byte(errmsg)
		//return err
	}

	a, _ := conn.RemoteAddr().(*net.TCPAddr)
	errmsg += " IP: " + a.IP.String()
	host, _, _ := net.SplitHostPort(addr + ":" + s.port)

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		errmsg := fmt.Sprintf("host: %s| error: connect failed2| error_msg: %v| ip: %s\n", addr, err, a.IP.String())
		s.errRecord <- []byte(errmsg)
		return err
	}

	defer c.Close()
	if err = c.Hello("EHLO"); err != nil {
		errmsg := fmt.Sprintf("host: %s| error: EHLO failed| error_msg: %v| ip: %s\n", addr, err, a.IP.String())
		s.errRecord <- []byte(errmsg)
		return err
	}

	// anything beyong this point will be part of tls logs
	var tlsrec = make(map[string]interface{})
	tlsrec["mx"] = addr
	tlsrec["port"] = s.port
	tlsrec["ip"] = a.IP

	if ok, _ := c.Extension("STARTTLS"); !ok {
		tlsrec["starttls"] = false
		s.LogMsg(tlsrec)
		return nil

	} else {
		if err = c.StartTLS(s.tlsConfig); err != nil {
			tlsrec["starttls"] = false
			tlsrec["starttls_errmsg"] = err
			// TODO do we need this?
			if state, ok := c.TLSConnectionState(); ok {
				for _, v := range state.PeerCertificates {
					log.Println(v.Subject)
				}
				//log.Println(state)
			}

			s.LogMsg(tlsrec)
			return nil
		}

		tlsrec["starttls"] = true
	}

	if state, ok := c.TLSConnectionState(); ok {

		s.ParsePeerX509Certs(addr, &state, tlsrec)
		s.LogMsg(tlsrec)
	}
	return c.Close()
}

// flush tls-info to file
func (s Scanner) LogMsg(tlsrec map[string]interface{}) {
	ret := true
	if s.exp != nil {
		ret = s.exp.Eval(tlsrec)
	}

	if ret {
		if s.ff != nil {
			tlsrec = s.ff.Run(tlsrec)
		}

		b, err := s.fmt.Do(tlsrec)
		if err != nil {
			log.Println(err)
		} else {

			if !s.quiet {
				fmt.Println(string(b))
			}

			b = append(b, '\n')
			s.record <- b
		}
	}
}

// used by -filter flag
var validOperators = map[string]bool{
	"=":    true,
	"!=":   true,
	">":    true,
	">=":   true,
	"<":    true,
	"<=":   true,
	"LIKE": true,
}

var keyType = map[string]string{
	ip:                   "string",
	host:                 "string",
	mx:                   "string",
	cipher:               "string",
	tls_version:          "string",
	x509_chain_depth:     "int",
	sig_alg:              "string",
	pubkey_alg:           "string",
	pubkey_size:          "int",
	key_usage:            "string",
	x509_ver:             "int",
	dns_names:            "string",
	dns_names_count:      "int",
	email_addresses:      "string",
	ip_addresses:         "string",
	issuer_serialno:      "string",
	issuer_cname:         "string",
	serialno:             "string",
	subject_cname:        "string",
	not_before:           "time.Time",
	not_after:            "time.Time",
	ext_key_usage:        "string",
	is_ca:                "bool",
	name_constr_domains:  "string",
	name_constr_critical: "bool",
	verify_cert:          "bool",
	verify_cert_errmsg:   "string",
	verify_host:          "bool",
	verify_host_errmsg:   "string",
	cert_expired:         "bool",
	valid_cert:           "bool",
}

const (
	ip                   = "ip"
	host                 = "host"
	mx                   = "mx"
	cipher               = "cipher"
	tls_version          = "tls_version"
	x509_chain_depth     = "x509_chain_depth"
	sig_alg              = "sig_alg"
	pubkey_alg           = "pubkey_alg"
	pubkey_size          = "pubkey_size"
	key_usage            = "key_usage"
	x509_ver             = "x509_ver"
	dns_names            = "dns_names"
	dns_names_count      = "dns_names_count"
	email_addresses      = "email_addresses"
	ip_addresses         = "ip_addresses"
	issuer_serialno      = "issuer_serialno"
	issuer_cname         = "issuer_cname"
	serialno             = "serialno"
	subject_cname        = "subject_cname"
	not_before           = "not_before"
	not_after            = "not_after"
	ext_key_usage        = "ext_key_usage"
	is_ca                = "is_ca"
	name_constr_domains  = "named_constr_domains"
	name_constr_critical = "named_constr_critical"
	verify_cert          = "verify_cert"
	verify_cert_errmsg   = "verify_cert_errmsg"
	verify_host          = "verify_host"
	verify_host_errmsg   = "verify_host_errmsg"
	cert_expired         = "cert_expired"
	valid_cert           = "valid_cert"
)

// Extract certificate info from TLS llstate object
func (s Scanner) ParsePeerX509Certs(addr string, state *tls.ConnectionState, tlsrec map[string]interface{}) {
	var level int
	var opts x509.VerifyOptions
	if s.certPool != nil {
		opts = x509.VerifyOptions{
			Roots:         s.certPool,
			Intermediates: x509.NewCertPool(),
		}
	} else {
		opts = x509.VerifyOptions{
			Intermediates: x509.NewCertPool(),
		}
	}

	for i, cert := range state.PeerCertificates {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}

	if _, err := state.PeerCertificates[0].Verify(opts); err != nil {
		tlsrec[verify_cert] = false
		tlsrec[verify_cert_errmsg] = err.Error()
	} else {
		tlsrec[verify_cert] = true
	}

	if err := state.PeerCertificates[0].VerifyHostname(addr); err != nil {
		tlsrec[verify_host] = false
		tlsrec[verify_host_errmsg] = err.Error()
	} else {
		tlsrec[verify_host] = true
	}

	if tlsrec[verify_host] == true && tlsrec[verify_cert] == true {
		tlsrec[valid_cert] = true
	} else {
		tlsrec[valid_cert] = false
	}

	certCnt := len(state.PeerCertificates)
	tlsrec[x509_chain_depth] = certCnt
	tlsrec[cipher] = GetCipherStr(state.CipherSuite)
	tlsrec[tls_version] = GetTLSVersionStr(state.Version)

	for _, v := range state.PeerCertificates {
		now := time.Now()
		if level == 0 {
			tlsrec[sig_alg] = GetSigAlgStr(v.SignatureAlgorithm)
			tlsrec[pubkey_alg] = GetPubKeyAlgStr(v.PublicKeyAlgorithm)
			tlsrec[pubkey_size] = GetPubKeySize(v.PublicKey, v.PublicKeyAlgorithm)
			tlsrec[key_usage] = GetKeyUsageStr(v.KeyUsage)
			tlsrec[x509_ver] = v.Version
			tlsrec[dns_names] = v.DNSNames
			tlsrec[dns_names_count] = len(v.DNSNames)
			if v.EmailAddresses != nil {
				tlsrec[email_addresses] = v.EmailAddresses
			}
			if len(v.IPAddresses) > 0 {
				tlsrec[ip_addresses] = fmt.Sprintf("%v", v.IPAddresses)
			}
			tlsrec[issuer_serialno] = fmt.Sprintf("%v", v.Issuer.SerialNumber)
			tlsrec[issuer_cname] = fmt.Sprintf("%v", v.Issuer.CommonName)
			tlsrec[serialno] = fmt.Sprintf("%v", v.SerialNumber)
			tlsrec[subject_cname] = fmt.Sprintf("%v", v.Subject.CommonName)
			tlsrec[not_before] = v.NotBefore
			tlsrec[not_after] = v.NotAfter
			tlsrec[ext_key_usage] = GetExtKeyUsageStrList(v.ExtKeyUsage)
			tlsrec[is_ca] = v.IsCA
			tlsrec[name_constr_domains] = v.PermittedDNSDomains
			tlsrec[name_constr_critical] = v.PermittedDNSDomainsCritical

			if now.Before(v.NotBefore) || now.After(v.NotAfter) {
				tlsrec[cert_expired] = true
			} else {
				tlsrec[cert_expired] = false
			}

		} else if level == certCnt-1 {
			tlsrec["sig_alg_ROOT"] = GetSigAlgStr(v.SignatureAlgorithm)
			tlsrec["pubkey_alg_ROOT"] = GetPubKeyAlgStr(v.PublicKeyAlgorithm)
			tlsrec["key_usage_ROOT"] = GetKeyUsageStr(v.KeyUsage)
			tlsrec["x509_ver_ROOT"] = v.Version
			tlsrec["issuer_serialno_ROOT"] = fmt.Sprintf("%v", v.Issuer.SerialNumber)
			tlsrec["issuer_cname_ROOT"] = fmt.Sprintf("%v", v.Issuer.CommonName)
			tlsrec["serialno_ROOT"] = fmt.Sprintf("%v", v.SerialNumber)
			tlsrec["subject_cname_ROOT"] = fmt.Sprintf("%v", v.Subject.CommonName)
			tlsrec["ext_key_usage_ROOT"] = fmt.Sprintf("%v", v.ExtKeyUsage)
			tlsrec["pubkey_size_ROOT"] = GetPubKeySize(v.PublicKey, v.PublicKeyAlgorithm)
			tlsrec["ext_key_usage_ROOT"] = GetExtKeyUsageStrList(v.ExtKeyUsage)
			tlsrec["is_ca_ROOT"] = v.IsCA
			tlsrec["name_constr_domains_ROOT"] = v.PermittedDNSDomains
			tlsrec["name_constr_critical_ROOT"] = v.PermittedDNSDomainsCritical
			if now.Before(v.NotBefore) || now.After(v.NotAfter) {
				tlsrec["cert_expired_ROOT"] = true
			} else {
				tlsrec["cert_expired_ROOT"] = false
			}

		} else {
			lvl := "_" + strconv.Itoa(level)
			tlsrec[sig_alg+lvl] = GetSigAlgStr(v.SignatureAlgorithm)
			tlsrec[pubkey_alg+lvl] = GetPubKeyAlgStr(v.PublicKeyAlgorithm)
			tlsrec[pubkey_size+lvl] = GetPubKeySize(v.PublicKey, v.PublicKeyAlgorithm)
			tlsrec[key_usage+lvl] = GetKeyUsageStr(v.KeyUsage)
			tlsrec[x509_ver+lvl] = v.Version
			tlsrec[issuer_serialno+lvl] = fmt.Sprintf("%v", v.Issuer.SerialNumber)
			tlsrec[issuer_cname+lvl] = fmt.Sprintf("%v", v.Issuer.CommonName)
			tlsrec[serialno+lvl] = fmt.Sprintf("%v", v.SerialNumber)
			tlsrec[subject_cname+lvl] = fmt.Sprintf("%v", v.Subject.CommonName)
			tlsrec[ext_key_usage+lvl] = fmt.Sprintf("%v", v.ExtKeyUsage)
			tlsrec[ext_key_usage+lvl] = GetExtKeyUsageStrList(v.ExtKeyUsage)
			tlsrec[is_ca+lvl] = v.IsCA
			tlsrec[name_constr_domains+lvl] = v.PermittedDNSDomains
			tlsrec[name_constr_critical+lvl] = v.PermittedDNSDomainsCritical
			if now.Before(v.NotBefore) || now.After(v.NotAfter) {
				tlsrec[cert_expired+lvl] = true
			} else {
				tlsrec[cert_expired+lvl] = false
			}
		}
		level += 1
	}
}

// CACerts builds an X.509 certificate pool from the given
// root CA bundle file.
func CACerts(certFile string) (*x509.CertPool, error) {
	cacerts, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Printf("Can't read CA cert file: %s error: %v\n", certFile, err)
		//log.Fatalf("Can't read CA cert file: %s error: %v\n", certFile, err)
		os.Exit(1)
	}

	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM([]byte(cacerts))
	if !ok {
		return nil, errors.New("PEMCertParseFailed")
	}
	return pool, nil
}

func GetExtKeyUsageStrList(k []x509.ExtKeyUsage) []string {
	var eku []string
	for _, e := range k {
		eku = append(eku, fmt.Sprintf("%s", GetExtKeyUsageStr(e)))
	}
	return eku
}

func GetKeyUsageStr(k x509.KeyUsage) string {
	switch k {
	case x509.KeyUsageDigitalSignature:
		return "DigitalSignature"
	case x509.KeyUsageContentCommitment:
		return "ContentCommitment"
	case x509.KeyUsageKeyEncipherment:
		return "KeyEncipherment"
	case x509.KeyUsageDataEncipherment:
		return "DataEncipherment"
	case x509.KeyUsageKeyAgreement:
		return "KeyAgreement"
	case x509.KeyUsageCertSign:
		return "CertSign"
	case x509.KeyUsageCRLSign:
		return "CRLSign"
	case x509.KeyUsageEncipherOnly:
		return "EncipherOnly"
	case x509.KeyUsageDecipherOnly:
		return "DecipherOnly"
	default:
		return "UNKNOWN"
	}
}

func GetExtKeyUsageStr(ek x509.ExtKeyUsage) string {
	switch ek {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSECEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSECTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSECUser"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "MicrosoftServerGatedCrypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "NetscapeServerGatedCrypto"
	default:
		return "UNKNOWN"
	}
}

func GetSigAlgStr(s x509.SignatureAlgorithm) string {
	switch s {
	case x509.UnknownSignatureAlgorithm:
		return "UnknownSigAlg"
	case x509.MD2WithRSA:
		return "RSA-MD2"
	case x509.MD5WithRSA:
		return "RSA-MD5"
	case x509.SHA1WithRSA:
		return "RSA-SHA1"
	case x509.SHA256WithRSA:
		return "RSA-SHA256"
	case x509.SHA384WithRSA:
		return "RSA-SHA384"
	case x509.SHA512WithRSA:
		return "RSA-SHA512"
	case x509.DSAWithSHA1:
		return "DSA-SHA1"
	case x509.DSAWithSHA256:
		return "DSA-SHA256"
	case x509.ECDSAWithSHA1:
		return "ECDSA-SHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSA-SHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSA-SHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSA-SHA512"
	default:
		return "UNKNOWN"
	}
}

func GetTLSVersionStr(c uint16) string {
	switch c {
	case 0x0300:
		return "SSLv3"
	case 0x0301:
		return "TLSv10"
	case 0x0302:
		return "TLSv11"
	case 0x0303:
		return "TLSv12"
	default:
		return "UNKNOWN"
	}
}

func GetCipherStr(c uint16) string {
	switch c {
	case 0x0005:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case 0x000a:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0x002f:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case 0x0035:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case 0x009c:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case 0x009d:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case 0xc007:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case 0xc009:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case 0xc00a:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case 0xc011:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case 0xc012:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0xc013:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case 0xc014:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case 0xc02f:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xc02b:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xc030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xc02c:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"

		// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
		// that the client is doing version fallback. See
		// https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00.
	case 0x5600:
		return "TLS_FALLBACK_SCSV"
	default:
		return "UNKNOWN_CIPHER"
	}
}

func GetPubKeyAlgStr(a x509.PublicKeyAlgorithm) string {

	switch a {
	case x509.UnknownPublicKeyAlgorithm:
		return "UnknownPublicKeyAlgorithm"
	case x509.RSA:
		return "RSA"
	case x509.DSA:
		return "DSA"
	case x509.ECDSA:
		return "ECDSA"
	default:
		return "UNKNOWN"
	}
}

func GetPubKeySize(p crypto.PublicKey, a x509.PublicKeyAlgorithm) int {
	switch a {
	case x509.UnknownPublicKeyAlgorithm:
		return -1
	case x509.RSA:
		pz := p.(*rsa.PublicKey)
		return pz.N.BitLen()
	case x509.DSA:
		return 1
	case x509.ECDSA:
		pz := p.(*ecdsa.PublicKey)
		return pz.X.BitLen()
	default:
		return 0
	}
}
