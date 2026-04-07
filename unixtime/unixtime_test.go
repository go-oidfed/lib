package unixtime

import (
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestUnixtime_Scan(t *testing.T) {
	tests := []struct {
		name        string
		input       any
		expected    time.Time
		expectError bool
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: time.Time{},
		},
		{
			name:     "valid time.Time",
			input:    time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC),
			expected: time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC),
		},
		{
			name:        "invalid type string",
			input:       "not a time",
			expectError: true,
		},
		{
			name:        "invalid type int",
			input:       12345,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u Unixtime
			err := u.Scan(tt.input)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, u.Time)
			}
		})
	}
}

func TestUnixtime_Value(t *testing.T) {
	tests := []struct {
		name     string
		unixtime Unixtime
		expected driver.Value
	}{
		{
			name:     "zero time returns nil",
			unixtime: Unixtime{},
			expected: nil,
		},
		{
			name:     "non-zero time returns time.Time",
			unixtime: Unixtime{Time: time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC)},
			expected: time.Date(2024, 1, 15, 12, 30, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := tt.unixtime.Value()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}

func TestUnixtime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    int64 // unix timestamp
		expectError bool
	}{
		{
			name:     "integer timestamp",
			input:    "1705322400",
			expected: 1705322400,
		},
		{
			name:     "float timestamp",
			input:    "1705322400.5",
			expected: 1705322400, // fractional part goes to nanoseconds
		},
		{
			name:     "zero",
			input:    "0",
			expected: 0,
		},
		{
			name:        "invalid JSON",
			input:       `"not a number"`,
			expectError: true,
		},
		{
			name:        "malformed JSON",
			input:       "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u Unixtime
			err := json.Unmarshal([]byte(tt.input), &u)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, u.Unix())
			}
		})
	}
}

func TestUnixtime_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		unixtime Unixtime
		expected string
	}{
		{
			name:     "zero time",
			unixtime: Unixtime{},
			expected: "0",
		},
		{
			name:     "non-zero time",
			unixtime: Unixtime{Time: time.Unix(1705322400, 0)},
			expected: "1705322400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.unixtime)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestUnixtime_JSONRoundTrip(t *testing.T) {
	original := Unixtime{Time: time.Unix(1705322400, 0)}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Unixtime
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Unix(), decoded.Unix())
}

func TestUntil(t *testing.T) {
	t.Run("future time", func(t *testing.T) {
		future := Unixtime{Time: time.Now().Add(time.Hour)}
		duration := Until(future)
		assert.True(t, duration > 0)
		assert.True(t, duration <= time.Hour)
	})

	t.Run("past time", func(t *testing.T) {
		past := Unixtime{Time: time.Now().Add(-time.Hour)}
		duration := Until(past)
		assert.True(t, duration < 0)
	})
}

func TestVerifyTime(t *testing.T) {
	now := time.Now()
	past := Unixtime{Time: now.Add(-time.Hour)}
	future := Unixtime{Time: now.Add(time.Hour)}

	tests := []struct {
		name        string
		iat         *Unixtime
		exp         *Unixtime
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid: iat in past, exp in future",
			iat:  &past,
			exp:  &future,
		},
		{
			name: "valid: nil iat, exp in future",
			iat:  nil,
			exp:  &future,
		},
		{
			name: "valid: iat in past, nil exp",
			iat:  &past,
			exp:  nil,
		},
		{
			name: "valid: both nil",
			iat:  nil,
			exp:  nil,
		},
		{
			name:        "invalid: iat in future (not yet valid)",
			iat:         &future,
			exp:         nil,
			expectError: true,
			errorMsg:    "not yet valid",
		},
		{
			name:        "invalid: exp in past (expired)",
			iat:         nil,
			exp:         &past,
			expectError: true,
			errorMsg:    "expired",
		},
		{
			name: "valid: zero iat",
			iat:  &Unixtime{},
			exp:  &future,
		},
		{
			name: "valid: zero exp",
			iat:  &past,
			exp:  &Unixtime{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyTime(tt.iat, tt.exp)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewDurationInSeconds(t *testing.T) {
	tests := []struct {
		name     string
		seconds  float64
		expected time.Duration
	}{
		{
			name:     "integer seconds",
			seconds:  60,
			expected: 60 * time.Second,
		},
		{
			name:     "fractional seconds",
			seconds:  1.5,
			expected: 1500 * time.Millisecond,
		},
		{
			name:     "zero",
			seconds:  0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDurationInSeconds(tt.seconds)
			assert.Equal(t, tt.expected, d.Duration)
		})
	}
}

func TestDurationInSeconds_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    time.Duration
		expectError bool
	}{
		{
			name:     "integer",
			input:    "60",
			expected: 60 * time.Second,
		},
		{
			name:     "float",
			input:    "1.5",
			expected: 1 * time.Second, // Note: implementation truncates to integer
		},
		{
			name:     "zero",
			input:    "0",
			expected: 0,
		},
		{
			name:        "invalid JSON",
			input:       `"not a number"`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d DurationInSeconds
			err := json.Unmarshal([]byte(tt.input), &d)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, d.Duration)
			}
		})
	}
}

func TestDurationInSeconds_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    time.Duration
		expectError bool
	}{
		{
			name:     "integer",
			input:    "60",
			expected: 60 * time.Second,
		},
		{
			name:     "float",
			input:    "1.5",
			expected: 1 * time.Second, // Note: implementation truncates to integer
		},
		{
			name:        "invalid YAML",
			input:       "not_a_number",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d DurationInSeconds
			err := yaml.Unmarshal([]byte(tt.input), &d)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, d.Duration)
			}
		})
	}
}

func TestDurationInSeconds_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		duration DurationInSeconds
		expected string
	}{
		{
			name:     "60 seconds",
			duration: DurationInSeconds{Duration: 60 * time.Second},
			expected: "60",
		},
		{
			name:     "zero",
			duration: DurationInSeconds{Duration: 0},
			expected: "0",
		},
		{
			name:     "fractional seconds",
			duration: DurationInSeconds{Duration: 1500 * time.Millisecond},
			expected: "1.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.duration)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestDurationInSeconds_MarshalYAML(t *testing.T) {
	tests := []struct {
		name     string
		duration DurationInSeconds
		expected float64
	}{
		{
			name:     "60 seconds",
			duration: DurationInSeconds{Duration: 60 * time.Second},
			expected: 60,
		},
		{
			name:     "zero",
			duration: DurationInSeconds{Duration: 0},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := tt.duration.MarshalYAML()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}

func TestDurationInSeconds_JSONRoundTrip(t *testing.T) {
	original := DurationInSeconds{Duration: 120 * time.Second}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded DurationInSeconds
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Duration, decoded.Duration)
}

func TestNow(t *testing.T) {
	before := time.Now()
	u := Now()
	after := time.Now()

	assert.True(t, !u.Time.Before(before), "Now() should not be before the test started")
	assert.True(t, !u.Time.After(after), "Now() should not be after the test ended")
}
