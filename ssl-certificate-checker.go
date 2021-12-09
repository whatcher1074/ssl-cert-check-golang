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
