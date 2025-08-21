package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type JSON map[string]interface{}

func (j JSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal JSONB value: %v", value)
	}
	
	// Handle empty bytes (empty JSON object from database)
	if len(bytes) == 0 {
		*j = JSON(make(map[string]interface{}))
		return nil
	}
	
	var result map[string]interface{}
	err := json.Unmarshal(bytes, &result)
	if err != nil {
		return err
	}
	*j = JSON(result)
	return nil
}

func (j JSON) MarshalJSON() ([]byte, error) {
	if j == nil {
		return []byte("null"), nil
	}
	return json.Marshal(map[string]interface{}(j))
}

func (j *JSON) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*j = nil
		return nil
	}
	
	var result map[string]interface{}
	err := json.Unmarshal(data, &result)
	if err != nil {
		return err
	}
	*j = JSON(result)
	return nil
}