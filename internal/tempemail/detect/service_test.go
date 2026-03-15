package detect

import (
	"context"
	"testing"
	"time"
)

func TestDisposableDomainDetection(t *testing.T) {
	service := NewService(10 * time.Minute)

	result, err := service.Check(context.Background(), CheckInput{
		Email: "test@mailinator.com",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	if !result.IsDisposable {
		t.Fatalf("expected disposable domain")
	}
	if result.RiskLevel != "high" && result.RiskLevel != "medium" {
		t.Fatalf("expected medium/high risk, got %q", result.RiskLevel)
	}
}

func TestInvalidEmail(t *testing.T) {
	service := NewService(10 * time.Minute)

	result, err := service.Check(context.Background(), CheckInput{
		Email: "invalid-email",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if result.ValidFormat {
		t.Fatalf("expected invalid format")
	}
	if result.RiskScore < 90 {
		t.Fatalf("expected high risk score, got %d", result.RiskScore)
	}
}
