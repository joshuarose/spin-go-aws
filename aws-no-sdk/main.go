package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"

	spinhttp "github.com/fermyon/spin/sdk/go/v2/http"
	"github.com/fermyon/spin/sdk/go/v2/variables"
)

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		// read config using spin variables
		err := initConfig()
		if err != nil {
			fmt.Println("Failed to read configuration:", err)
			http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
			return
		}

		// Create a new HTTP request
		req, err := http.NewRequest("GET", fmt.Sprintf("https://s3.%s.amazonaws.com/", config.region), nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
			return
		}

		// Set the AWS authentication headers
		req.Header.Set("Authorization", getAuthorizationHeader(req))
		req.Header.Set("x-amz-date", time.Now().UTC().Format("20060102T150405Z"))
		req.Header.Set("x-amz-security-token", config.sessionToken)
		req.Header.Set("x-amz-content-sha256", getPayloadHash(""))

		// Send the HTTP request
		resp, err := spinhttp.Send(req)

		if err != nil {
			fmt.Println("Error sending request:", err)
			http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response:", err)
			http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
			return
		}

		// Parse the XML response
		var listBucketsResponse ListBucketsResponse
		err = xml.Unmarshal(body, &listBucketsResponse)
		if err != nil {
			fmt.Println("Body:", string(body))
			fmt.Println("Error parsing XML response:", err)
			http.Error(w, "Internal Server Error Occurred", http.StatusInternalServerError)
			return
		}

		// Print the list of buckets
		fmt.Println("S3 Buckets:")
		var buckets string
		for _, bucket := range listBucketsResponse.Buckets.Bucket {
			buckets += bucket.Name + " "
		}

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, buckets)
	})
}

func main() {
	/*
	 *	In Spin environment, the handler function has to be wired up during the init function
	 *  because Spin will call into the wasi export named spin_http_handle_http_request
	 *  so we need to set the default handler during the init function which is called
	 *  before the exported spin_http_handle_http_request function in our SDK
	 *  spinhttp.Handle: https://github.com/fermyon/spin-go-sdk/blob/48ddef7a261725f771f987323b213b0696c655ef/http/http.go#L93
	 *  internals.go:    https://github.com/fermyon/spin-go-sdk/blob/48ddef7a261725f771f987323b213b0696c655ef/http/internals.go#L16
	 */
}

type AWSConfig struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	region          string
	service         string
}

type ListBucketsResponse struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Buckets struct {
		Bucket []struct {
			Name         string `xml:"Name"`
			CreationDate string `xml:"CreationDate"`
		} `xml:"Bucket"`
	} `xml:"Buckets"`
}

type ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

/*
 * By default, Spin's security model does not pass through environment
 * variables from the host to the guest. The recommended way to provide
 * configuration is via "variables" that are defined in spin.toml
 * and can be overridden by setting an environment variable like:
 * `export SPIN_VARIABLE_AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"`
 */

var config AWSConfig

func initConfig() error {
	accessKeyID, err := variables.Get("aws_access_key_id")
	if err != nil {
		return err
	}
	secretAccessKey, err := variables.Get("aws_secret_access_key")
	if err != nil {
		return err
	}
	sessionToken, err := variables.Get("aws_session_token")
	if err != nil {
		return err
	}
	region, err := variables.Get("aws_default_region")
	if err != nil {
		return err
	}
	config = AWSConfig{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		sessionToken:    sessionToken,
		region:          region,
		service:         "s3",
	}
	return nil
}

func getAuthorizationHeader(req *http.Request) string {
	// Get the current time
	now := time.Now().UTC()

	// Create the canonical request
	canonicalRequest := getCanonicalRequest(req, now)

	// Create the string to sign
	stringToSign := getStringToSign(canonicalRequest, now)

	// Calculate the signature
	signature := getSignature(stringToSign, now)

	// Create the authorization header
	authorizationHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=%s",
		config.accessKeyID, now.Format("20060102"), config.region, config.service, signature)

	return authorizationHeader
}

func getCanonicalRequest(req *http.Request, now time.Time) string {
	// Create the canonical URI
	canonicalURI := "/"

	// Create the canonical query string
	canonicalQueryString := ""

	// Create the canonical headers
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\nx-amz-security-token:%s\n",
		req.Host, getPayloadHash(""), now.Format("20060102T150405Z"), config.sessionToken)

	// Create the signed headers
	signedHeaders := "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"

	// Create the payload hash
	payloadHash := sha256.New()
	payloadHash.Write([]byte(""))
	payloadHashString := hex.EncodeToString(payloadHash.Sum(nil))

	// Combine all the components to create the canonical request
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method, canonicalURI, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHashString)

	return canonicalRequest
}

func getStringToSign(canonicalRequest string, now time.Time) string {
	// Create the hash of the canonical request
	canonicalRequestHash := sha256.New()
	canonicalRequestHash.Write([]byte(canonicalRequest))
	canonicalRequestHashString := hex.EncodeToString(canonicalRequestHash.Sum(nil))

	// Create the string to sign
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
		now.Format("20060102T150405Z"), now.Format("20060102"), config.region, config.service, canonicalRequestHashString)

	return stringToSign
}

func getSignature(stringToSign string, now time.Time) string {
	// Create the signing key
	dateKey := hmacSHA256([]byte("AWS4"+config.secretAccessKey), []byte(now.Format("20060102")))
	regionKey := hmacSHA256(dateKey, []byte(config.region))
	serviceKey := hmacSHA256(regionKey, []byte(config.service))
	signingKey := hmacSHA256(serviceKey, []byte("aws4_request"))

	// Calculate the signature
	signature := hmacSHA256(signingKey, []byte(stringToSign))

	return hex.EncodeToString(signature)
}

func hmacSHA256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func getPayloadHash(payload string) string {
	hash := sha256.New()
	hash.Write([]byte(payload))
	return hex.EncodeToString(hash.Sum(nil))
}
