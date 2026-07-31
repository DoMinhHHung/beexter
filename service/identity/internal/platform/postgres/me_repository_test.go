package postgres

import (
	"context"
	"errors"
	"testing"

	getmeapp "github.com/DoMinhHHung/beexster/service/identity/internal/application/getme"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

func TestMeRepositoryMapsNoRows(t *testing.T) {
	t.Parallel()

	repository, err := NewMeRepository(meDatabaseStub{
		queryRow: func(context.Context, string, ...any) pgx.Row {
			return meRowStub{scan: func(...any) error { return pgx.ErrNoRows }}
		},
	})
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}

	_, err = repository.FindByID(
		context.Background(),
		identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
	)
	if !errors.Is(err, getmeapp.ErrIdentityNotFound) {
		t.Fatalf("expected identity-not-found, got %v", err)
	}
}

type meDatabaseStub struct {
	queryRow func(context.Context, string, ...any) pgx.Row
}

func (s meDatabaseStub) QueryRow(
	ctx context.Context,
	sql string,
	args ...any,
) pgx.Row {
	return s.queryRow(ctx, sql, args...)
}

type meRowStub struct {
	scan func(...any) error
}

func (s meRowStub) Scan(dest ...any) error {
	return s.scan(dest...)
}
