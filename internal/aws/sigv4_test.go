package aws

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSign(t *testing.T) {
	tests := []struct {
		name      string
		region    string
		service   string
		accessID  string
		secretKey string
		request   func() *http.Request
		now       time.Time
		expErr    string
		expAuth   string
	}{
		{
			name:      "get object",
			region:    "us-east-1",
			service:   "s3",
			accessID:  "AKIAIOSFODNN7EXAMPLE",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
				req.Header.Set("Range", "bytes=0-9")
				return req
			},
			now:     time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC),
			expAuth: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name:      "put object",
			region:    "us-east-1",
			service:   "s3",
			accessID:  "AKIAIOSFODNN7EXAMPLE",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			request: func() *http.Request {
				body := "Welcome to Amazon S3."
				req, _ := http.NewRequest("PUT", "https://examplebucket.s3.amazonaws.com/test$file.text", strings.NewReader(body))
				req.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
				req.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
				return req
			},
			now:     time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC),
			expAuth: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name:      "get bucket lifecycle",
			region:    "us-east-1",
			service:   "s3",
			accessID:  "AKIAIOSFODNN7EXAMPLE",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/?lifecycle", nil)
				return req
			},
			now:     time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC),
			expAuth: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name:      "list objects",
			region:    "us-east-1",
			service:   "s3",
			accessID:  "AKIAIOSFODNN7EXAMPLE",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
				return req
			},
			now:     time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC),
			expAuth: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := test.request()
			cfg := Config{
				Region:    test.region,
				Service:   test.service,
				AccessKey: test.accessID,
				SecretKey: test.secretKey,
			}
			err := Sign(req, cfg, test.now)
			if err != nil {
				if test.expErr == "" {
					t.Fatalf("unexpected error: %s", err.Error())
				}
				if !strings.Contains(err.Error(), test.expErr) {
					t.Fatalf("unexpected error: %s", err.Error())
				}
				return
			}
			if test.expErr != "" {
				t.Fatal("error did not occur")
			}

			auth := req.Header.Get("Authorization")
			if auth != test.expAuth {
				t.Fatalf("unexpected auth header: %s", auth)
			}
		})
	}
}
