package detect

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
)

type Service struct {
	cacheTTL time.Duration
	nowFn    func() time.Time

	mu    sync.RWMutex
	cache map[string]cachedResult
}

type cachedResult struct {
	result CheckResult
	expiry time.Time
}

type CheckInput struct {
	Email string `json:"email"`
}

type CheckResult struct {
	Email              string     `json:"email"`
	NormalizedEmail    string     `json:"normalized_email"`
	Domain             string     `json:"domain"`
	ValidFormat        bool       `json:"valid_format"`
	IsDisposable       bool       `json:"is_disposable"`
	KnownSpamProvider  bool       `json:"known_spam_provider"`
	DomainCreatedAt    *time.Time `json:"domain_created_at,omitempty"`
	DomainAgeDays      int        `json:"domain_age_days,omitempty"`
	DomainAgeAvailable bool       `json:"domain_age_available"`
	RiskScore          int        `json:"risk_score"`
	RiskLevel          string     `json:"risk_level"`
	RiskReasons        []string   `json:"risk_reasons,omitempty"`
}

func NewService(cacheTTL time.Duration) *Service {
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Minute
	}
	return &Service{
		cacheTTL: cacheTTL,
		nowFn:    func() time.Time { return time.Now().UTC() },
		cache:    make(map[string]cachedResult),
	}
}

func (s *Service) Check(ctx context.Context, input CheckInput) (CheckResult, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" {
		return CheckResult{}, errors.New("email is required")
	}

	if cached, ok := s.getCache(email); ok {
		return cached, nil
	}

	result := CheckResult{
		Email:           input.Email,
		NormalizedEmail: email,
	}

	parsed, err := mail.ParseAddress(email)
	if err != nil {
		result.ValidFormat = false
		result.RiskScore = 95
		result.RiskLevel = "high"
		result.RiskReasons = []string{"invalid email format"}
		s.setCache(email, result)
		return result, nil
	}

	result.ValidFormat = true
	parts := strings.Split(parsed.Address, "@")
	if len(parts) != 2 {
		result.RiskScore = 95
		result.RiskLevel = "high"
		result.RiskReasons = []string{"invalid email format"}
		s.setCache(email, result)
		return result, nil
	}

	domain := strings.ToLower(strings.TrimSpace(parts[1]))
	result.Domain = domain
	result.IsDisposable = isDisposableDomain(domain)
	result.KnownSpamProvider = isKnownSpamProvider(domain)
	s.enrichDomainAge(ctx, domain, &result)
	s.computeRisk(&result)

	s.setCache(email, result)
	return result, nil
}

func (s *Service) enrichDomainAge(ctx context.Context, domain string, result *CheckResult) {
	raw, err := whois.Whois(domain)
	if err != nil {
		return
	}

	created := parseWhoisCreationDate(raw)
	if created == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}

	result.DomainCreatedAt = created
	result.DomainAgeAvailable = true
	result.DomainAgeDays = int(s.nowFn().Sub(*created).Hours() / 24)
}

func (s *Service) computeRisk(result *CheckResult) {
	score := 0
	reasons := make([]string, 0, 6)

	if !result.ValidFormat {
		score += 95
		reasons = append(reasons, "invalid email format")
	}
	if result.IsDisposable {
		score += 65
		reasons = append(reasons, "disposable email provider")
	}
	if result.KnownSpamProvider {
		score += 40
		reasons = append(reasons, "known spam-associated provider")
	}
	if result.DomainAgeAvailable {
		switch {
		case result.DomainAgeDays < 0:
			score += 20
			reasons = append(reasons, "domain creation date in the future")
		case result.DomainAgeDays < 30:
			score += 30
			reasons = append(reasons, "domain younger than 30 days")
		case result.DomainAgeDays < 180:
			score += 15
			reasons = append(reasons, "domain younger than 6 months")
		}
	} else {
		score += 10
		reasons = append(reasons, "domain age unavailable")
	}

	if score > 100 {
		score = 100
	}
	result.RiskScore = score
	result.RiskReasons = reasons
	switch {
	case score >= 70:
		result.RiskLevel = "high"
	case score >= 35:
		result.RiskLevel = "medium"
	default:
		result.RiskLevel = "low"
	}
}

func (s *Service) getCache(email string) (CheckResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, ok := s.cache[email]
	if !ok || s.nowFn().After(item.expiry) {
		return CheckResult{}, false
	}
	return item.result, true
}

func (s *Service) setCache(email string, result CheckResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache[email] = cachedResult{
		result: result,
		expiry: s.nowFn().Add(s.cacheTTL),
	}
}

func isDisposableDomain(domain string) bool {
	_, ok := disposableDomains[domain]
	return ok
}

func isKnownSpamProvider(domain string) bool {
	_, ok := spamProviders[domain]
	return ok
}
