package main

import (
	"asterfusion/client/logger"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"crypto/rsa"
	"crypto/ecdsa"	
	"encoding/json"
	"encoding/pem"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"os/exec"
	"bytes"

	"github.com/fullsailor/pkcs7"
)

type CloudDiscoveryCfg struct {
	MacAddress                     string          `json:"mac_address"`
	ControllerEndpoint             string          `json:"controller_endpoint"`
	Metadata                       string          `json:"metadata"`
	OrganizationId                 string          `json:"organization_id"`
	CreateAt                       string          `json:"created_at"`
	UpdateAt                       string          `json:"updated_at"`
}

const (
	CONFIG_DB       DBType = 4
	STATE_DB        DBType = 6
)

const (
	ucentralCertPath       = "/etc/ucentral/certs/"
	certPath               = "/etc/ucentral/certs/cert.pem"
	keyPath                = "/etc/ucentral/certs/key.pem"
	casPath                = "/etc/ucentral/certs/cas.pem"
	operationalPath        = "/etc/ucentral/certs/operational.pem"
	operationalCAPath      = "/etc/ucentral/certs/operational.ca"
)

var (
	ConfigDb  *RedisSingleObj
	StateDb  *RedisSingleObj
)

var (
	cloudDiscoveryHost     	= "https://discovery.open-lan.org/v1/devices/"
	estHost   				= "est.certificates.open-lan.org"
)

func GetSerialNum() (string, error) {
	deviceMac := ""
	isExist, _ := ConfigDb.Db.HExists("DEVICE_METADATA|localhost", "mac").Result()

	if isExist {
		// configdb
		mac, err := ConfigDb.Db.HGet("DEVICE_METADATA|localhost", "mac").Result()
		if err != nil {
			fmt.Printf("Failed to get serial number: %s\n", err.Error())
			return "", err
		}
		deviceMac = mac
	} else {
		// statedb
		mac, err := StateDb.Db.HGet("DEVICE_METADATA|localhost", "mac").Result()
		if err != nil {
			fmt.Printf("Failed to get serial number: %s\n", err.Error())
			return "", err
		}
		deviceMac = mac
	}

	devivceMacStr := strings.Replace(deviceMac, ":", "", -1)
	return devivceMacStr, nil
}

func tlsclient (verifyCa bool) (*http.Client, error) {
	client := &http.Client{}

	_, err := ioutil.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("Reading %s failed, err is %s\n", keyPath, err.Error())
		return client, err
	}

	certPem := operationalPath
	hasOperationalPem := true
	_, err = ioutil.ReadFile(operationalPath)
	if err != nil {
		hasOperationalPem = false
		certPem = certPath
	}

	if !hasOperationalPem {
		_, err := ioutil.ReadFile(certPath)
		if err != nil {
			fmt.Printf("Reading %s failed, err is %s\n", certPath, err.Error())
			return client, err
		}		
	}

	cert, err := tls.LoadX509KeyPair(certPem, keyPath)
	if err != nil {
		fmt.Printf("load client pem failed, err is %s\n",  err.Error())
		return client, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS12,
		SessionTicketsDisabled: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(0), 
	}

	if verifyCa {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(casPath)
		if err != nil {
			fmt.Printf("Reading %s failed, err is %s:", casPath, err.Error())
		} else {
			caCertPool.AppendCertsFromPEM(caCert)
		}
		opreationalCaCert, err := os.ReadFile(operationalCAPath)
		if err != nil {
			fmt.Printf("Reading %s failed, err is %s:", operationalCAPath, err.Error())
		} else {
			caCertPool.AppendCertsFromPEM(opreationalCaCert)
		}
		tlsConfig.RootCAs = caCertPool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
	}
	return client, nil
}

func getControllerUrl() string {
	ControllerUrl := ""
	client, err := tlsclient(true)
	if err != nil {
		fmt.Printf("tls client created failed, err is %s\n",  err.Error())
		return ControllerUrl
	}

	SerialNum, _ := GetSerialNum()
	redirectorUrl := cloudDiscoveryHost + SerialNum

	resp, err := client.Get(redirectorUrl)
	if err != nil {
		fmt.Printf("request failed, err is %s\n",  err.Error())
		return ControllerUrl
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("read response failed, err is %s\n",  err.Error())
		return ControllerUrl
	}

	bodyStr := string(body)

	var dataAttr = CloudDiscoveryCfg{}

	err = json.Unmarshal([]byte(bodyStr), &dataAttr)
	if err != nil {
		fmt.Printf("Unmarshal firstcontact json file failed, Error: %s\n", err.Error())
		return ControllerUrl
	}

	if dataAttr.ControllerEndpoint != "" {
		ControllerUrl = dataAttr.ControllerEndpoint
	}

	return ControllerUrl
}

func getEstServer(domain string) []string {
	CAA := []string{}

	// Execute the dig command to retrieve CAA records
	cmd := exec.Command("dig", "+short", "caa", domain)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf("command dig failed, err is %s\n",  err.Error())
		return CAA
	}

	output := strings.TrimSpace(out.String())
	if output == "" {
		return CAA
	}

	// Split each row and extract the third field
	lines := strings.Split(output, "\n")
	var thirdFields []string

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			thirdField := fields[2]
			thirdField = strings.Trim(thirdField, `"`)
			thirdFields = append(thirdFields, thirdField)
		}
	}

	for _, field := range thirdFields {
		CAA = append(CAA, field)
	}

	return CAA
}

// Obtain signature algorithm based on private key type
func getSignatureAlgorithm(privateKey interface{}) x509.SignatureAlgorithm {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return x509.SHA256WithRSA
	case *ecdsa.PrivateKey:
		return x509.ECDSAWithSHA256
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

func getOperationalCA(estServer string) bool {
	result := false
	client, err := tlsclient(true)
	if err != nil {
		fmt.Printf("tls client created failed, err is %s\n",  err.Error())
		return result
	}

	caUrl := "https://" + estServer + "/cacerts"
	resp, err := client.Get(caUrl)
	if err != nil {
		fmt.Printf("request %s failed, err is %s\n", caUrl, err.Error())
		return result
	}
	defer resp.Body.Close()

	fmt.Printf("%s resp.StatusCode %d\n", caUrl, resp.StatusCode)

	calist, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("read %s response failed, err is %s\n",caUrl, err.Error())
		return result
	}

	decoded, err := base64.StdEncoding.DecodeString(string(calist))
    if err != nil {
		fmt.Printf("Decode String failed, err is %s",  err.Error())
		return result
    }

    certPEM := decoded

	// parse PKCS#7 data
	p7, err := pkcs7.Parse(certPEM)
	if err != nil {
		fmt.Printf("parse PKCS7 failed, err is %s",  err.Error())
		return result
	}

	var certs []*x509.Certificate
	if p7.Certificates != nil {
		certs = p7.Certificates
	}

	logger.Info("Converted P7 to PEM")

	if len(certs) == 0 {
		fmt.Printf("cannot find operational.ca from response")
		return result
	}

	// save to operational.ca
	file, err := os.Create(operationalCAPath)
	if err != nil {
		fmt.Printf("cannot create opreational.ca, err is %s",  err.Error())
		return result
	}
	defer file.Close()

	for _, cert := range certs {
		err = pem.Encode(file, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			fmt.Printf("write opreational.ca failed, err is %s",  err.Error())
			return result
		}
	}

	fmt.Printf("Persistently stored operational.ca\n")
	return true
}

func getOperationalCert(estServer string, reenroll bool) bool {
	result := false
	// Read existing private key file (PEM format)
	fmt.Printf("start to get operational.pem\n")
	privateKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("read %s failed, err is %s\n", keyPath, err.Error())
		return result
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		fmt.Printf("Invalid private key PEM format private key\n")
		return result
	}

	// parse private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("parse private key failed, err is %s\n", err.Error())
		return result
	}

	pemData := []byte{}
	if !reenroll {
		pemData, err = ioutil.ReadFile(certPath)
		if err != nil {
			fmt.Printf("read %s failed, err is %s\n", certPath, err.Error())
			return result
		}
	} else {
		pemData, err = ioutil.ReadFile(operationalPath)
		if err != nil {
			fmt.Printf("read %s failed, err is %s\n", operationalPath, err.Error())
			return result
		}
	}

	blockCert, _ := pem.Decode(pemData)
	if blockCert == nil || blockCert.Type != "CERTIFICATE" {
		fmt.Printf("Invalid cert key PEM format cert key\n")
		return result
	}

	cert, err := x509.ParseCertificate(blockCert.Bytes)
	if err != nil {
		fmt.Printf("parse cert key failed, err is %s\n", err.Error())
		return result
	}

	subjectCert := cert.Subject

	subject := pkix.Name{
		CommonName:         subjectCert.CommonName,
		Organization:       subjectCert.Organization,
	}

	// create CSR template
	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: getSignatureAlgorithm(privateKey),
	}


	// create CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		fmt.Printf("create CSR failed, err is %s\n", err.Error())
		return result
	}

	fmt.Printf("Generated CSR\n")

	encoded := base64.StdEncoding.EncodeToString(csrBytes)
	reader := strings.NewReader(encoded)

	caURL := "https://" + estServer + "/simpleenroll"
	if reenroll {
		caURL = "https://" + estServer + "/simplereenroll"
	}

	req, _ := http.NewRequest("POST", caURL, reader)
	req.Header.Set("Content-Type", "application/pkcs10-base64")
	req.Header.Set("Accept", "application/pkcs7")

	client, err := tlsclient(true)
	if err != nil {
		fmt.Printf("tls client created failed, err is %s\n",  err.Error())
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("request %s failed, err is %s\n",  caURL, err.Error())
		return result
	}

	fmt.Printf("EST succeeded\n")

	defer resp.Body.Close()


	certPEM, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("read response %s failed, err is %s\n", caURL, err.Error())
		return result
	}

	decoded, err := base64.StdEncoding.DecodeString(string(certPEM))
    if err != nil {
		fmt.Printf("Decode String failed, err is %s\n",  err.Error())
		return result
    }

    certPEM = decoded

	// parse PKCS#7 data
	p7, err := pkcs7.Parse(certPEM)
	if err != nil {
		fmt.Printf("parse PKCS7 failed, err is %s\n",  err.Error())
		return result
	}

	var certs []*x509.Certificate
	if p7.Certificates != nil {
		certs = p7.Certificates
	}

	fmt.Printf("Converted P7 to PEM\n")

	if len(certs) == 0 {
		fmt.Printf("cannot find operational certificate from response\n")
		return result
	}

	// save to operational.pem
	file, err := os.Create(operationalPath)
	if err != nil {
		fmt.Printf("cannot create opreational.pem, err is %s\n",  err.Error())
		return result
	}
	defer file.Close()

	for _, cert := range certs {
		err = pem.Encode(file, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			fmt.Printf("write opreational.pem failed, err is %s\n",  err.Error())
			return result
		}
	}

	fmt.Printf("Persistently stored operational.pem\n")
	result = true
	return result
}

func Enroll(reenroll bool) bool {
	ControllerAddr := getControllerUrl()

	estServerList := getEstServer(ControllerAddr)
	estServerList = append(estServerList, estHost)

	for _, oneServer := range estServerList {
		getOperationalCA(oneServer)
		res := getOperationalCert(oneServer, reenroll)
		if res{
			break
		}
	}
	return true
}

func Cacerts() {
	ControllerAddr := getControllerUrl()

	estServerList := getEstServer(ControllerAddr)
	estServerList = append(estServerList, estHost)

	for _, oneServer := range estServerList {
		res := getOperationalCA(oneServer)
		if res{
			break
		}
	}
}


func setQAorProduct() bool {
	result := false
	pemData, err := ioutil.ReadFile(certPath)
	if err != nil {
		fmt.Printf("read %s failed, err is %s", certPath, err.Error())
		return result
	}

	blockCert, _ := pem.Decode(pemData)
	if blockCert == nil || blockCert.Type != "CERTIFICATE" {
		fmt.Printf("Invalid PEM format cert key")
		return result
	}

	cert, err := x509.ParseCertificate(blockCert.Bytes)
	if err != nil {
		fmt.Printf("parse cert key failed, err is %s", err.Error())
		return result
	}

	issue := cert.Issuer.String()
	fmt.Printf("(Issuer): %s\n", issue)
	if strings.Contains(issue, "OpenLAN Demo") {
		estHost = "qaest.certificates.open-lan.org:8001"
		cloudDiscoveryHost = "https://discovery-qa.open-lan.org/v1/devices/"
	}
	
	return true
}

func main() {
	os.Setenv("GODEBUG", "x509ignoreCN=0")
	_ = setQAorProduct()
	ConfigDb, _ = ConnectToRedis(CONFIG_DB)
	StateDb, _ = ConnectToRedis(STATE_DB)
	if os.Geteuid() != 0 {
		fmt.Printf("Please add 'sudo' Before the command\n")
		return
	}
	if len(os.Args) == 2 {
		firstArg := os.Args[1]
		if firstArg == "enroll" {
			Enroll(false)
		} else if firstArg == "reenroll" {
			Enroll(true)
		} else if firstArg == "cacerts" {
			Cacerts()
		} else {
			fmt.Printf("Only supports three methods:\nsudo est_client enroll\nsudo est_client reenroll\nsudo est_client cacerts\n")
		}
	} else {
		fmt.Printf("Only supports three methods:\nsudo est_client enroll\nsudo est_client reenroll\nsudo est_client cacerts\n")
	}
}
