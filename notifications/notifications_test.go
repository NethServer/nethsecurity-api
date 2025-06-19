package notifications

import (
	"database/sql"
	_ "embed"
	"os"
	"testing"
)

//go:embed schema.sql
var databaseSchema string

func TestNotificationRepositorySqlite(t *testing.T) {
	// init database
	databaseFile := "test.sqlite"
	_, _ = os.Create(databaseFile)
	connection, err := sql.Open("sqlite3", databaseFile)
	AssertNull(t, err)
	_, err = connection.Exec(databaseSchema)
	AssertNull(t, err)

	// create repository
	repo, err := New(databaseFile)
	AssertNull(t, err)
	
	t.Run("add notifications", func(t *testing.T) {
		want := Notification{
			content: "test notification",
		}
		err := repo.AddNotification(want)
		AssertNull(t, err)
		stmt, err := repo.connection.Prepare("SELECT * FROM notifications")
		defer stmt.Close()
		AssertNull(t, err)
		rows, err := stmt.Query()
		defer rows.Close()
		AssertNull(t, err)
		if !rows.Next() {
			t.Fatalf("No notifications created.")
		}
		var got Notification
		if err := rows.Scan(&got.id, &got.content, &got.createdAt); err != nil {
			t.Fatalf("Failed to scan notification: %v", err)
		}
		if got.content != want.content {
			t.Errorf("Expected content %s, got %s", want.content, got.content)
		}
	})
}

func AssertNull(t *testing.T, got any) {
	t.Helper()
	if got != nil {
		t.Errorf("Expected nil, got %v", got)
	}
}

func CompareList[T comparable](t *testing.T, got, want []T) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("Expected length %d, got %d", len(want), len(got))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("At index %d: expected %v, got %v", i, want[i], got[i])
		}
	}
}
