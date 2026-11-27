package server

import (
	"encoding/json"
)

func (checks ChecksInfo) MarshalJSON() ([]byte, error) {
	type orderedChecks struct {
		Database  string `json:"database"`
		Cache     string `json:"cache"`
		Disk      string `json:"disk"`
		Scheduler string `json:"scheduler"`
		Tor       string `json:"tor,omitempty"`
		I2P       string `json:"i2p,omitempty"`
	}
	base, err := json.Marshal(orderedChecks{
		Database: checks.Database, Cache: checks.Cache, Disk: checks.Disk,
		Scheduler: checks.Scheduler, Tor: checks.Tor, I2P: checks.I2P,
	})
	if err != nil {
		return nil, err
	}
	if len(checks.Datasets) == 0 {
		return base, nil
	}
	result := make([]byte, 0, len(base)+len(checks.Datasets)*32)
	result = append(result, base[:len(base)-1]...)
	for _, check := range checks.Datasets {
		key, marshalErr := json.Marshal(check.Key)
		if marshalErr != nil {
			return nil, marshalErr
		}
		status, marshalErr := json.Marshal(check.Status)
		if marshalErr != nil {
			return nil, marshalErr
		}
		result = append(result, ',')
		result = append(result, key...)
		result = append(result, ':')
		result = append(result, status...)
	}
	result = append(result, '}')
	return result, nil
}
