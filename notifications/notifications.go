package notifications

import "database/sql"
import _ "github.com/mattn/go-sqlite3"

type Notification struct {
	id        int
	content   string
	createdAt string
}

type NotificationRepository interface {
	ListNotifications() ([]Notification, error)
	AddNotification(Notification) error
	DeleteNotification(Notification) error
}

type NotificationRepositorySqlite struct {
	connection *sql.DB
}

func New(path string) (*NotificationRepositorySqlite, error) {
	connection, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return &NotificationRepositorySqlite{connection: connection}, nil
}

func (r *NotificationRepositorySqlite) AddNotification(notification Notification) error {
	_, err := r.connection.Exec("INSERT INTO notifications (content) VALUES (?)", notification.content)

	return err
}
