package main

/*   This is a simply converision of ssl-cert-check with a few needed additions for jks checking and cert updates using golang config commands.

Program: SSL Certificate Check <ssl-cert-check>

*/

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/gomail.v2"
)

const (
	layoutUTC      = "2006-01-02"
	PROGRAMVERSION = 4.15
)

type DataValues struct {
	PageSupport   string
	Sender        string
	Warndays      int
	Quiet         bool
	Alarm         bool
	PkcsPasswd    string
	CerType       string
	Awk           string
	Date          string
	Grep          string
	OpenSSL       string
	Sed           string
	MkTemp        string
	Find          string
	PrintF        string
	CertTmp       string
	ErrorTmp      string
	Subject       string
	Smtp_Host     string
	Smtp_Port     int
	User_Auth     string
	User_Password string
	ServerURL     string
	ServerPort    int
	TlsFlag       string
	TLSServerName bool
	Options       string
	CertFile      string
	Host          string
	Port          int
}

var CertData = new(DataValues)

func init() {
	// adding loggin into here later

	// Set up channel on which to send signal notifications.
	// We must use a buffered channel or risk missing the signal
	// if we're not ready to receive when the signal is sent.
	c := make(chan os.Signal, 1)

	// Passing no signals to Notify means that
	// all signals will be sent to the channel.
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGKILL)

	// Block until any signal is received.
	// Cleanup temp files if they exist

	go func() {
		for {
			s := <-c
			fmt.Println("Received signal from channel :", s)
			switch s {
			default:
				fmt.Printf("got signal = %v \n", s)
			case syscall.SIGINT:
				fmt.Println("Signal interrupt triggered.")
				os.Exit(1)
			case syscall.SIGQUIT:
				fmt.Println("Signal quit triggered.")
				os.Exit(0)

			case syscall.SIGKILL:
				fmt.Println("got Kill signal/SIGKILL")
				os.Exit(0)

			case syscall.SIGTERM:
				fmt.Println("Signal Terminate triggered.")
				os.Exit(0)

			}

		}
		os.Exit(0)
	}()

	cleanup() // run clean up of dummy temp data which technically shouldnt exists at all.
}

func main() {

	CertData.ServerURL = "stackoverflow.com"
	CertData.Port = 443

	check_server_status(CertData.Port, CertData.ServerURL)
}

func send_mail() {
	email := DataValues{}
	email.PageSupport = "wendellhatcher1074@gmail.com"
	email.Sender = "wendellhatcher1074@gmail.com"
	email.Smtp_Host = "smtp.gmail.com"
	email.Smtp_Port = 465
	email.User_Password = "lamar10131974"
	m := gomail.NewMessage()
	m.SetHeader("From", email.PageSupport)
	m.SetHeader("To", email.Sender)
	m.SetHeader("Subject", "Testing Some Crap!")
	m.SetBody("text/html", "Hello <b>Dell</b> and <i>Crap</i>!")
	d := gomail.NewDialer(email.Smtp_Host, email.Smtp_Port, email.PageSupport, email.User_Password)

	// Send the email to Bob, Cora and Dan.
	if err := d.DialAndSend(m); err != nil {
		panic(err)
	}

}

func cleanup() {
	// removing dummy tmp cert data if it still exists which it shouldnt.
	CertData.CertTmp = "/tmp"
	data, err := ioutil.ReadDir(CertData.CertTmp)
	if err != nil {
		fmt.Printf("failed reading directory: %s", err)
	}

	fmt.Printf("\nNumber of files in current directory: %d", len(data))
	fmt.Printf("\nError: %v", err)

	if len(data) != 0 {
		for _, file := range data {

			err = os.RemoveAll(path.Join([]string{CertData.CertTmp, file.Name()}...))
			if err != nil {
				panic(err)

			}
			fmt.Println(data, "removed!")
		}

	}

}

/*
##########################################
# Purpose: Describe how the script works
# Arguments:
#   None
##########################################
*/
func usage() {

	fmt.Println("Usage: $0 [ -e email address ] [-E sender email address] [ -x days ] [-q] [-a] [-b] [-h] [-i] [-n] [-N] [-v]    { [ -s common_name ] && [ -p port] } || { [ -f cert_file ] } || { [ -c cert file ] } || { [ -d cert dir ] }")
	fmt.Println("")
	fmt.Println("  -a                : Send a warning message through E-mail")
	fmt.Println("  -b                : Will not print header")
	fmt.Println("  -c cert file      : Print the expiration date for the PEM or PKCS12 formatted certificate in cert file")
	fmt.Println("  -d cert directory : Print the expiration date for the PEM or PKCS12 formatted certificates in cert directory")
	fmt.Println("  -e E-mail address : E-mail address to send expiration notices")
	fmt.Println("  -E E-mail sender  : E-mail address of the sender")
	fmt.Println("  -f cert file      : File with a list of FQDNs and ports")
	fmt.Println("  -h                : Print this screen")
	fmt.Println("  -i                : Print the issuer of the certificate")
	fmt.Println("  -k password       : PKCS12 file password")
	fmt.Println("  -n                : Run as a Nagios plugin")
	fmt.Println("  -N                : Run as a Nagios plugin and output one line summary (implies -n, requires -f or -d)")
	fmt.Println("  -p port           : Port to connect to (interactive mode)")
	fmt.Println("  -q                : Don't print anything on the console")
	fmt.Println("  -s commmon name   : Server to connect to (interactive mode)")
	fmt.Println("  -S                : Print validation information")
	fmt.Println("  -t type           : Specify the certificate type")
	fmt.Println("  -V                : Print version information")
	fmt.Println("  -x days           : Certificate expiration interval (eg. if cert_date < days)")
	fmt.Println("")

}

/*
##########################################################################
# Purpose: Connect to a server ($1) and port ($2) to see if a certificate
#          has expired
# Arguments:
#   $1 -> Server name
#   $2 -> TCP port to connect to
##########################################################################
*/
func check_server_status(port int, server string) {
	var ServerPort int = port
	var ServerURL string = server

	server_port := ServerURL + ":" + strconv.Itoa(ServerPort)
	conn, err := tls.Dial("tcp", server_port, nil)
	if err != nil {
		panic("Server doesn't support SSL certificate err: " + err.Error())
	}

	err = conn.VerifyHostname(ServerURL)
	if err != nil {
		panic("Hostname doesn't match with certificate: " + err.Error())
	}

	var encodedCert bytes.Buffer
	err = pem.Encode(&encodedCert, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: conn.ConnectionState().PeerCertificates[0].Raw,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	p, err := x509.MarshalPKIXPublicKey(conn.ConnectionState().PeerCertificates[0].PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	publicKey := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: p,
	}))

	// take this data and modify it so it goes into an email config struct call later
	fmt.Print("Issuer: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].Issuer)
	fmt.Print("\nSubject: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].Subject)
	fmt.Print("\nSerial Number: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].SerialNumber)
	fmt.Print("\nVersion: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].Version)
	fmt.Print("\nNot Before: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].NotBefore)
	fmt.Print("\nNot After: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].NotAfter)
	fmt.Print("\nEmail Addresses: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].EmailAddresses)
	fmt.Print("\nIP Addresses: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].IPAddresses)
	fmt.Print("\nPermitted DNS Domains: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].PermittedDNSDomains)
	fmt.Print("\nExcluded DNS Domains: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].ExcludedDNSDomains)
	fmt.Print("\nPermitted IP Ranges: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].PermittedIPRanges)
	fmt.Print("\nEXcluded IP Ranges: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].ExcludedIPRanges)
	fmt.Print("\nPermitted Email Addresses: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].PermittedEmailAddresses)
	fmt.Print("\nExcluded Email Addresses: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].ExcludedEmailAddresses)
	fmt.Print("\nPermitted URI Domains: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].PermittedURIDomains)
	fmt.Print("\nExlucded URI Domains: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].ExcludedURIDomains)
	fmt.Print("\nOCSP Server: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].OCSPServer)
	fmt.Print("\nIssuing Certificate URL Server: ")
	fmt.Print(conn.ConnectionState().PeerCertificates[0].IssuingCertificateURL)
	fmt.Print("\nDNS Names: ")
	fmt.Println(conn.ConnectionState().PeerCertificates[0].DNSNames)
	fmt.Println("\nPublic Key: ")
	fmt.Println(publicKey)
	fmt.Println("Cert: ")
	fmt.Println(encodedCert.String())

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter

	CurrentTime := time.Now()
	CurrentTimePlus60 := CurrentTime.AddDate(0, 0, 60)
	CurrentTimePlus30 := CurrentTime.AddDate(0, 0, 30)
	CurrentT := CurrentTime.Format(layoutUTC)
	CurrentT60 := CurrentTimePlus60.Format(layoutUTC)
	CurrentT30 := CurrentTimePlus30.Format(layoutUTC)
	expire := expiry.Format(layoutUTC)
	fmt.Println("This is the current time: ", CurrentT)
	fmt.Println("This is the current time plus 60 days", CurrentT60)
	fmt.Println("This is the current time plus 30 days", CurrentT30)

	fmt.Println("This is the expired date time:", expire)
	// add in dummy code block here to later call email with past datetime stamps for certs over 30 to 60 days old using switch case.
	TimeCaseVal := expire
	if TimeCaseVal <= CurrentT {
		fmt.Println("Send some type of email for over 60 days cert issue")
	}

	if TimeCaseVal <= CurrentTimePlus30.String() {
		fmt.Println("Send some type of email for over 30 days cert issue")
	}

	if TimeCaseVal <= CurrentTime.String() {
		fmt.Println("Send some type of email for 0 days left cert issue")
	}

}
