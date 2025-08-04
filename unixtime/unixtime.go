package unixtime

import (
	"encoding/json"
	"math"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// Unixtime is a type for handling unix timestamps
type Unixtime struct {
	time.Time
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (u *Unixtime) UnmarshalJSON(src []byte) error {
	var f float64
	if err := json.Unmarshal(src, &f); err != nil {
		return err
	}
	sec, dec := math.Modf(f)
	u.Time = time.Unix(int64(sec), int64(dec*(1e9)))
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (u Unixtime) MarshalJSON() ([]byte, error) {
	if u.IsZero() {
		return json.Marshal(0)
	}
	return json.Marshal(u.Unix())
}

// Until returns the time.Duration from now until an Unixtime
func Until(u Unixtime) time.Duration {
	return time.Until(u.Time)
}

// VerifyTime verifies the iat and exp times with regard to the current time
func VerifyTime(iat, exp *Unixtime) error {
	now := time.Now()
	if iat != nil && !iat.IsZero() && iat.After(now) {
		return errors.New("not yet valid")
	}
	if exp != nil && !exp.IsZero() && exp.Before(now) {
		return errors.New("expired")
	}
	return nil
}

// NewDurationInSeconds returns a DurationInSeconds from a number of seconds
func NewDurationInSeconds(seconds float64) DurationInSeconds {
	return DurationInSeconds{time.Duration(seconds * float64(time.Second))}
}

// DurationInSeconds is a type for handling time.Duration expressed in seconds
type DurationInSeconds struct {
	time.Duration
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *DurationInSeconds) UnmarshalJSON(src []byte) error {
	var f float64
	if err := json.Unmarshal(src, &f); err != nil {
		return err
	}
	*d = DurationInSeconds{time.Duration(f) * time.Second}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (d *DurationInSeconds) UnmarshalYAML(value *yaml.Node) error {
	var f float64
	if err := value.Decode(&f); err != nil {
		return err
	}
	*d = DurationInSeconds{time.Duration(f) * time.Second}
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (d DurationInSeconds) MarshalJSON() ([]byte, error) {
	return json.Marshal(float64(d.Nanoseconds()) / 1e9)
}

// MarshalYAML implements the yaml.Marshaler interface.
func (d DurationInSeconds) MarshalYAML() (any, error) {
	return float64(d.Nanoseconds()) / float64(time.Second), nil
}

func Now() Unixtime {
	return Unixtime{time.Now()}
}
