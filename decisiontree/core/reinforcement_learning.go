package core

import "blackwater/decisiontree/database"

type ReinforcementLearner = database.ReinforcementLearner

type TransitionStats = database.TransitionStats

type SQLiteReinforcementLearner = database.SQLiteReinforcementLearner

func NewSQLiteReinforcementLearner(databasePath string) (*SQLiteReinforcementLearner, error) {
	return database.NewSQLiteReinforcementLearner(databasePath)
}
