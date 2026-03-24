package core

import "blackwater/decisiontree/database"

type AuditLogger = database.AuditLogger

type AuditEvent = database.AuditEvent

type SQLiteAuditLogger = database.SQLiteAuditLogger

func NewSQLiteAuditLogger(databasePath string) (*SQLiteAuditLogger, error) {
	return database.NewSQLiteAuditLogger(databasePath)
}
