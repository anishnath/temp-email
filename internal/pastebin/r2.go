package pastebin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const r2KeyPrefix = "pastes/"

// R2Store implements ContentStore using Cloudflare R2.
type R2Store struct {
	client *s3.Client
	bucket string
}

// NewR2Store creates an R2 content store. Returns nil if config is incomplete.
func NewR2Store(cfg *Config) (*R2Store, error) {
	if cfg.R2AccessKeyID == "" || cfg.R2SecretAccessKey == "" {
		return nil, fmt.Errorf("R2 config incomplete: access_key, secret_key required")
	}
	endpoint := strings.TrimSpace(cfg.R2Endpoint)
	if endpoint == "" && cfg.R2AccountID != "" {
		endpoint = "https://" + cfg.R2AccountID + ".r2.cloudflarestorage.com"
	}
	if endpoint == "" {
		return nil, fmt.Errorf("R2 config incomplete: R2_ENDPOINT or R2_ACCOUNT_ID required")
	}

	// Use custom endpoint resolver (matches onecompiler working R2 setup)
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:           endpoint,
			SigningRegion: "auto",
		}, nil
	})

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			strings.TrimSpace(cfg.R2AccessKeyID),
			strings.TrimSpace(cfg.R2SecretAccessKey),
			"",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true // R2 requires path-style addressing
	})
	return &R2Store{client: client, bucket: cfg.R2BucketName}, nil
}

func (s *R2Store) key(id string) string {
	return r2KeyPrefix + id
}

// Put stores content in R2.
func (s *R2Store) Put(ctx context.Context, key string, data []byte, contentType string) error {
	k := s.key(key)
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(k),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
	})
	return err
}

// Get retrieves content from R2.
func (s *R2Store) Get(ctx context.Context, key string) ([]byte, string, error) {
	k := s.key(key)
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(k),
	})
	if err != nil {
		return nil, "", err
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, "", err
	}
	ct := ""
	if out.ContentType != nil {
		ct = *out.ContentType
	}
	return data, ct, nil
}

// Delete removes content from R2.
func (s *R2Store) Delete(ctx context.Context, key string) error {
	k := s.key(key)
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(k),
	})
	return err
}
