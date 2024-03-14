package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	_ "github.com/aws/aws-sdk-go-v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	spinhttp "github.com/fermyon/spin/sdk/go/v2/http"
)

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		var buckets string

		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"))
		if err != nil {
			log.Fatalf("unable to load SDK config, %v", err)
		}
		svc := s3.NewFromConfig(cfg)
		o, err := svc.ListBuckets(context.Background(), &s3.ListBucketsInput{})
		for i := 0; i < len(o.Buckets); i++ {
			buckets += *o.Buckets[i].Name + " "
		}
		w.Header().Set("Content-Type", "application/html")
		fmt.Fprintf(w, "Buckets: %s", buckets)
	})
}

func main() {}
