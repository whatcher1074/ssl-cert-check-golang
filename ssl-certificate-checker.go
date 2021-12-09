<<<<<<< HEAD
package main

/*   This is a simply converision of ssl-cert-check with a few needed additions for jks checking and cert updates using golang config commands.

Program: SSL Certificate Check <ssl-cert-check>

*/

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
     "io"
	"gopkg.in/gomail.v2"
	"crypto/tls"
	"time"
)

const PROGRAMVERSION = 4.15

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
	ServerURL  string
	ServerPort int
	TlsFlag string
	TLSServerName bool
	Options string
	CertFile string 
	Host  string 
	Port int 
 }

var CertData = DataValues{}
CertData.CertTmp =  ""
CertData.ErrorTmp = ""


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
	if data, err : = ioutil.ReadDir(CertData.CertTmp)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {
		err = os.Remove(data)
		if err != nil {
			panic(err)

		}
		fmt.Println(data, "removed!")
	}

	   
	if data_2, err : = ioutil.ReadDir(CertData.ErrorTmp)
	if err != nil {
		return nil, err
	}
	if len(data_2) != 0 {
		err = os.Remove(data_2)
		if err != nil {
			panic(err)

		}
		fmt.Println(data_2, "removed!")
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
    fmt.Println( "  -E E-mail sender  : E-mail address of the sender")
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
func check_server_status() {
   CertData.ServerPort  
   CertData.ServerURL 
 
   //check the URL is setup with the proper certificate remote url connection call and then the expiration date. 
   //come back and do the date expired diff correctly then email to group

   conn, err := tls.Dial("tcp", CerData.ServerURL:CertDataServerPort, nil)
	if err != nil {
		panic("Server doesn't support SSL certificate err: " + err.Error())
	}

	err = conn.VerifyHostname(CerData.ServerURL)
	if err != nil {
		panic("Hostname doesn't match with certificate: " + err.Error())
	}

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	fmt.Printf("Issuer: %s\nExpiry: %v\n", conn.ConnectionState().PeerCertificates[0].Issuer, expiry.Format(time.RFC850))
    
   
=======
package main

/*   This is a simply converision of ssl-cert-check with a few needed additions for jks checking and cert updates using golang config commands.

Program: SSL Certificate Check <ssl-cert-check>

*/

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
     "io"
	"gopkg.in/gomail.v2"
	"crypto/tls"
	"time"
)

const PROGRAMVERSION = 4.15

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
	ServerURL  string
	ServerPort int
	TlsFlag string
	TLSServerName bool
	Options string
	CertFile string 
	Host  string 
	Port int 
 }

var CertData = DataValues{}
CertData.CertTmp =  ""
CertData.ErrorTmp = ""  
CertData.Host =  ""

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
	if data, err : = ioutil.ReadDir(CertData.CertTmp)
	if err != nil {
		return nil, err
	}
	if len(data) != 0 {
		err = os.Remove(data)
		if err != nil {
			panic(err)

		}
		fmt.Println(data, "removed!")
	}

	   
	if data_2, err : = ioutil.ReadDir(CertData.ErrorTmp)
	if err != nil {
		return nil, err
	}
	if len(data_2) != 0 {
		err = os.Remove(data_2)
		if err != nil {
			panic(err)

		}
		fmt.Println(data_2, "removed!")
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
    fmt.Println( "  -E E-mail sender  : E-mail address of the sender")
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
func check_server_status() {
   CertData.ServerPort  
   CertData.ServerURL 
 
   //check the URL is setup with the proper certificate remote url connection call and then the expiration date. 
   //come back and do the date expired diff correctly then email to group

   conn, err := tls.Dial("tcp", CerData.ServerURL:CertDataServerPort, nil)
	if err != nil {
		panic("Server doesn't support SSL certificate err: " + err.Error())
	}

	err = conn.VerifyHostname(CerData.ServerURL)
	if err != nil {
		panic("Hostname doesn't match with certificate: " + err.Error())
	}

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	fmt.Printf("Issuer: %s\nExpiry: %v\n", conn.ConnectionState().PeerCertificates[0].Issuer, expiry.Format(time.RFC850))
    
   
>>>>>>> f3763c50f97d5e0ed28172622616da35687fc367
}