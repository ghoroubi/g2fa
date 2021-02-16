/*
Package implements the OTP algorithms supported by Google Authenticator.
Copyright 2020 , Nima Ghoroubi (ghoroubi85@gmail.com), All rights reserved.

This package supports below algorithms:
1- HOTP algorithm (refer to RFC 4226 for more info about algorithm)
2- TOTP algorithm (refer to RFC 6238 for more info about algorithm)
*/

package ngg2fa

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"net/url"
	"sort"
	"strconv"
	"time"
)


// ComputeCode computes the response code for a 64-bit challenge 'value' using the secret 'secret'.
// To avoid breaking compatibility with the previous API, it returns an invalid code (-1) when an error occurs,
// but does not silently ignore them (it forces a mismatch so the code will be rejected).
func ComputeCode(secret string, value int64) int {

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return -1
	}

	hash := hmac.New(sha1.New, key)
	err = binary.Write(hash, binary.BigEndian, value)
	if err != nil {
		return -1
	}
	h := hash.Sum(nil)

	offset := h[19] & 0x0f

	truncated := binary.BigEndian.Uint32(h[offset : offset+4])

	truncated &= 0x7fffffff
	code := truncated % 1000000

	return int(code)
}



func (c *OTPConfig) checkScratchCodes(code int) bool {

	for i, v := range c.ScratchCodes {
		if code == v {
			// remove this code from the list of valid ones
			l := len(c.ScratchCodes) - 1
			c.ScratchCodes[i] = c.ScratchCodes[l] // copy last element over this element
			c.ScratchCodes = c.ScratchCodes[0:l]  // and trim the list length by 1
			return true
		}
	}

	return false
}

func (c *OTPConfig) checkHotpCode(code int) bool {

	for i := 0; i < c.WindowSize; i++ {
		if ComputeCode(c.Secret, int64(c.HotpCounter+i)) == code {
			c.HotpCounter += i + 1
			// We don't check for overflow here, which means you can only authenticate 2^63 times
			// After that, the counter is negative and the above 'if' test will fail.
			// This matches the behaviour of the PAM module.
			return true
		}
	}

	// we must always advance the counter if we tried to authenticate with it
	c.HotpCounter++
	return false
}

func (c *OTPConfig) checkTotpCode(t0, code int) bool {

	minT := t0 - (c.WindowSize / 2)
	maxT := t0 + (c.WindowSize / 2)
	for t := minT; t <= maxT; t++ {
		if ComputeCode(c.Secret, int64(t)) == code {

			if c.PreventedTimestamps != nil {
				for _, timeCode := range c.PreventedTimestamps {
					if timeCode == t {
						return false
					}
				}

				// code hasn't been used before
				c.PreventedTimestamps = append(c.PreventedTimestamps, t)

				// remove all time codes outside of the valid window
				sort.Ints(c.PreventedTimestamps)
				min := 0
				for c.PreventedTimestamps[min] < minT {
					min++
				}
				// FIXME: check we don't have an off-by-one error here
				c.PreventedTimestamps = c.PreventedTimestamps[min:]
			}

			return true
		}
	}

	return false
}

// Authenticate a OTP against the given OTPConfig
// Returns true/false if the authentication was successful.
// Returns error if the password is incorrectly formatted (not a zero-padded 6 or non-zero-padded 8 digit number).
func (c *OTPConfig) Authenticate(password string) (bool, error) {

	var scratch bool

	switch {
	case len(password) == 6 && password[0] >= '0' && password[0] <= '9':
		break
	case len(password) == 8 && password[0] >= '1' && password[0] <= '9':
		scratch = true
		break
	default:
		return false, ErrInvalidCode
	}

	code, err := strconv.Atoi(password)

	if err != nil {
		return false, ErrInvalidCode
	}

	if scratch {
		return c.checkScratchCodes(code), nil
	}

	// we have a counter value we can use
	if c.HotpCounter > 0 {
		return c.checkHotpCode(code), nil
	}

	var t0 int
	// assume we're on Time-based OTP
	if c.UTC {
		t0 = int(time.Now().UTC().Unix() / 30)
	} else {
		t0 = int(time.Now().Unix() / 30)
	}
	return c.checkTotpCode(t0, code), nil
}

// ProvisionURI generates a URI that can be turned into a QR code to configure
// a Google Authenticator mobile app.
func (c *OTPConfig) ProvisionURI(user string) string {
	return c.ProvisionWithIssuer(user, "")
}

// ProvisionWithIssuer generates a URI that can be turned into a QR code
// to configure a Google Authenticator mobile app. It respects the recommendations
// on how to avoid conflicting accounts.
//
// See https://github.com/google/google-authenticator/wiki/Conflicting-Accounts
func (c *OTPConfig) ProvisionWithIssuer(user string, issuer string) string {
	auth := TOTP
	q := make(url.Values)
	if c.HotpCounter > 0 {
		auth = HOTP
		q.Add("counter", strconv.Itoa(c.HotpCounter))
	}
	q.Add("secret", c.Secret)
	if issuer != "" {
		q.Add("issuer", issuer)
		auth += issuer + ":"
	}

	return "otpauth://" + auth + user + "?" + q.Encode()
}
