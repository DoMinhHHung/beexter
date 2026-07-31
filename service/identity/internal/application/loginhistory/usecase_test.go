package loginhistory

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

func TestExecutePaginatesLoginHistory(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 31, 5, 0, 0, 0, time.UTC)
	repository := &loginHistoryRepositoryStub{attempts: []Attempt{
		{ID: "1", IPAddress: netip.MustParseAddr("192.0.2.1"), AttemptedAt: now},
		{ID: "2", IPAddress: netip.MustParseAddr("192.0.2.2"), AttemptedAt: now.Add(-time.Minute)},
		{ID: "3", IPAddress: netip.MustParseAddr("192.0.2.3"), AttemptedAt: now.Add(-2 * time.Minute)},
	}}
	useCase, err := New(repository)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	output, err := useCase.Execute(
		context.Background(),
		Input{
			UserID: identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
			Limit:  2,
		},
	)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(output.Attempts) != 2 || output.NextBefore == nil {
		t.Fatalf("unexpected output: %+v", output)
	}
	if !output.NextBefore.Equal(now.Add(-time.Minute)) {
		t.Fatalf("unexpected cursor: %s", output.NextBefore)
	}
	if repository.limit != 3 {
		t.Fatalf("repository must receive limit+1, got %d", repository.limit)
	}
}

type loginHistoryRepositoryStub struct {
	attempts []Attempt
	limit    int
}

func (s *loginHistoryRepositoryStub) List(
	_ context.Context,
	_ identity.ID,
	limit int,
	_ *time.Time,
) ([]Attempt, error) {
	s.limit = limit
	return s.attempts, nil
}
