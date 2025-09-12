package utils

import (
	"archive/tar"
	"asterfusion/client/logger"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"strconv"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

// writes a json response to a WebSocket connection.
func WriteWebsocketJSONResponse(conn *websocket.Conn, res any) (err error) {
	resJSON, err := json.Marshal(res)
	if err != nil {
		logger.Error("Failed to convert response to JSON: %s", err.Error())
		return err
	}

	err = conn.WriteMessage(websocket.TextMessage, []byte(resJSON))
	if err != nil {
		logger.Error("Failed to write message to websocket: %s", err.Error())
		return err
	}

	return nil
}

// Writes a json response to a WebSocket connection.
// use rw lock
func SyncWriteWebsocketJSONResponse(conn *websocket.Conn, mux *sync.RWMutex, res any) (err error) {
	resJSON, err := json.Marshal(res)
	if err != nil {
		logger.Error("Failed to convert response to JSON: %s", err.Error())
		return err
	}

	mux.Lock()
	err = conn.WriteMessage(websocket.TextMessage, []byte(resJSON))
	mux.Unlock()

	if err != nil {
		logger.Error("Failed to write message to websocket: %s", err.Error())
		return err
	}

	return nil
}

// Writes a json response to a WebSocket connection.
// use rw lock
func SyncWriteWebsocketWithJsonResponse(conn *websocket.Conn, mux *sync.RWMutex, res []byte) (err error) {
	mux.Lock()
	err = conn.WriteMessage(websocket.TextMessage, res)
	mux.Unlock()

	if err != nil {
		logger.Error("Failed to write message to websocket: %s", err.Error())
		return err
	}

	return nil
}

// WaitUntilSometime - Block the program until the specified time.
//
//	@param when - Timestamp.The number of seconds elapsed since January 1, 1970 UTC.
func WaitUntilSometime(when int64) {
	if when <= 0 {
		return
	}

	for {
		current := time.Now().Unix()
		if current >= when {
			break
		}
		logger.Info("Wait until sometime(unix) %v.Current time(unix) is %v.", when, current)
		time.Sleep(1000 * time.Millisecond)
	}
}

func FindIndex(slice []string, val string) int {
	for idx, item := range slice {
		if item == val {
			return idx
		}
	}
	return len(slice)
}

func MD5Str(str string) ([]byte, error) {
	h := md5.New()
	_, err := io.WriteString(h, str)
	if err != nil {
		logger.Error("Failed to get MD5 info: %s", err.Error())
		return nil, err
	}
	return h.Sum(nil), nil
}

func MD5File(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		logger.Error("Failed to get MD5 info: %s", err.Error())
		return nil, err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		logger.Error("Failed to get MD5 info: %s", err.Error())
		return nil, err
	}
	return h.Sum(nil), nil
}

func ConvertToSerialNumber(macStr string) (string, error) {
	// Parse the MAC address string
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return "", fmt.Errorf("invalid MAC address: %s", macStr)
	}

	// Remove the separators from the MAC address
	serial := strings.ReplaceAll(mac.String(), ":", "")
	serial = strings.ReplaceAll(serial, "-", "")

	// Return the device serial number
	return serial, nil
}

func unpadPKCS7(plaintext []byte) ([]byte, error) {
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}

	for i := 0; i < padding; i++ {
		if plaintext[len(plaintext)-1-i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}

func DecryptAES(ciphertext, key, iv string) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
				logger.Warn(fmt.Sprintf("%s", e.Error()))
			} else {
				err = errors.New(fmt.Sprint(r))
				logger.Warn(fmt.Sprintf("%+v", r))
			}
		}
	}()

	keyBytes := []byte(key)[:32]
	ivBytes := []byte(iv)[:16]

	decodedCipherText, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	decrypter := cipher.NewCBCDecrypter(block, ivBytes)
	plaintext := make([]byte, len(decodedCipherText))
	decrypter.CryptBlocks(plaintext, decodedCipherText)

	plaintext, err = unpadPKCS7(plaintext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func isTCPSocket(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func isUDPSocket(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}

func setSocketOptions(network, address string, c syscall.RawConn, interfaceName string) (err error) {
	if interfaceName == "" || (!isTCPSocket(network) && !isUDPSocket(network)) {
		return
	}

	err = c.Control(func(fd uintptr) {
		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && !ip.IsGlobalUnicast() {
			return
		}

		if innerErr := unix.BindToDevice(int(fd), interfaceName); innerErr != nil {
			return
		}
	})
	return
}

func UploadFile(path string, uri string, vrf string) error {
	client := &http.Client{
		Timeout: 30 * time.Minute,
	}

	if vrf != "" {
		dialer := &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				return setSocketOptions(network, address, c, vrf)
			},
		}
		client.Transport = &http.Transport{
			DialContext: dialer.DialContext,
		}
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0750)
	if err != nil {
		logger.Error("An error occurred while open file %s: %s", path, err.Error())
		return fmt.Errorf("Failed to open file: %v", err)
	}
	defer f.Close()

	restyClient := resty.NewWithClient(client)
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, err := restyClient.R().
		SetMultipartField("data", "file", "application/octet-stream", f).
		Post(uri)
	if err != nil {
		logger.Error("An error occurred while uploading file: %s", err.Error())
		return fmt.Errorf("Failed to upload file: %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		logger.Error("Failed to download file %s. Server returned non-200 status code: %d.", path, resp.StatusCode())
		return fmt.Errorf("Server returned non-200 status code: %d", resp.StatusCode())
	}

	logger.Info("Upload file %s successfully.", path)
	return nil
}

func DownloadFile(path string, uri string, vrf string, token string) error {
	client := &http.Client{
		Timeout: 60 * time.Minute,
	}

	if vrf != "" {
		dialer := &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				return setSocketOptions(network, address, c, vrf)
			},
		}
		client.Transport = &http.Transport{
			DialContext: dialer.DialContext,
		}
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0750)
	if err != nil {
		logger.Error("An error occurred while create file %s: %s", path, err.Error())
		return fmt.Errorf("Failed to create file: %v", err)
	}
	defer f.Close()

	restyClient := resty.NewWithClient(client)
	if token != "" {
		restyClient.SetHeader("Authorization", "Bearer "+token)
	}
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	resp, err := restyClient.R().SetOutput(path).Get(uri)
	if err != nil {
		logger.Error("An error occurred while downloading file: %s", err.Error())
		return fmt.Errorf("Failed to download file: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		logger.Error("Failed to download file %s. Server returned non-200 status code: %d.", path, resp.StatusCode())
		return fmt.Errorf("Server returned non-200 status code: %d", resp.StatusCode())
	}

	logger.Info("Downloaded file %s successfully.", path)
	return nil
}

// CompressBlobToTarGz compresses the given content into a tar.gz file.
func CompressBlobToTarGz(content []byte, dest string, hdr *tar.Header) error {
	// Create a new file at the specified destination path.
	fw, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer fw.Close()

	// Create a gzip.Writer to write compressed data into the target file.
	gw := gzip.NewWriter(fw)
	defer gw.Close()

	// Create a tar.Writer to write data into the gzip.Writer.
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// If no header is provided, create a default header with name "data", mode 0644,
	// size equal to the length of the content, and modification time set to the current UTC time.
	if hdr == nil {
		hdr = &tar.Header{
			Name:    "data",
			Mode:    0644,
			Size:    int64(len(content)),
			ModTime: time.Now().UTC(),
		}
	}

	// Write the header to the beginning of the tar file.
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	// Write the source content to the tar file.
	if _, err := io.Copy(tw, bytes.NewReader(content)); err != nil {
		return err
	}

	// Return nil if successful, or an error if there is any issue creating or writing to the files.
	return nil
}

func RemoveWhiteSpace(str string) string {
	reg := regexp.MustCompile(`[\s]+`)
	return reg.ReplaceAllString(str, "")
}

func RoundToFixed(num float64, precision int) float64 {
	output := math.Pow(10, float64(precision))
	return math.Round(num*output) / output
}

func IsSubstingInStringArray(substring string, array []string) bool {
	result := false
	for _, item := range array {
		if strings.Contains(item, substring) {
			result = true
			return result
		}
	}
	return result
}

func IPversion(ipAddress string) int {
	parsedIP := net.ParseIP(ipAddress)

	if parsedIP == nil {
		return 0
	}

	if parsedIP.To4() != nil {
		return 4
	} else {
		return 6
	}
}

func RemoveIPMask(ip string) string {
	if strings.Contains(ip, "/") {
		parts := strings.Split(ip, "/")
		return parts[0]
	}
	return ip
}

func Ipv4MaskToint(netmask string) int {
	ipSplitArr := strings.Split(netmask, ".")
	if len(ipSplitArr) != 4 {
		return 32
	}
	ipv4MaskArr := make([]byte, 4)
	for i, value := range ipSplitArr {
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return 32
		}
		if intValue > 255 {
			return 32
		}
		ipv4MaskArr[i] = byte(intValue)
	}

	ones, _ := net.IPv4Mask(ipv4MaskArr[0], ipv4MaskArr[1], ipv4MaskArr[2], ipv4MaskArr[3]).Size()
	return ones
}