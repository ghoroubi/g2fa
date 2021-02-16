package ngg2fa

import (
	"errors"
)

const (
	// TOTP , acronym for TimeBased algorithm.
	TOTP = "totp/"

	// HOTP , acronym for Counter based algorithm.
	HOTP = "hotp/"
)

// ErrInvalidCode indicate the supplied one-time code was not valid
var ErrInvalidCode = errors.New("invalid code")

// OTPConfig
// Authenticate method modifies this object, you should store codes for preventing code reuse.
type OTPConfig struct {
	// User Secret
	Secret string `json:"secret" validate:"required"`

	// The higher value, the higher security.
	WindowSize int `json:"window_size" validate:"number,min=0,max=100"`

	// The counter of current generated otp,only if counter-based chosen.
	HotpCounter int `json:"hotp_counter" validate:"omitempty"`

	// Timestamps in the current window.
	PreventedTimestamps []int `json:"disallow_reuse" validate:"omitempty"`

	// A collection of integer codes that are for authentication.
	ScratchCodes []int `json:"scratch_codes" validate:"omitempty"`

	// Setting UTC to TRUE changes timestamp to UTC rather than local time.
	UTC bool `json:"utc" validate:"omitempty"`
}
