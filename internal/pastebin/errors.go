package pastebin

import "errors"

var (
	ErrNotFound           = errors.New("paste not found")
	ErrExpired            = errors.New("paste expired")
	ErrBurned             = errors.New("paste already viewed (burn-after-read)")
	ErrInvalidExpiry      = errors.New("invalid expiry")
	ErrPassphraseRequired = errors.New("passphrase required")
	ErrWrongPassphrase    = errors.New("wrong passphrase")
	ErrSlugTaken          = errors.New("slug already taken")
	ErrContentTooLarge    = errors.New("content too large")
	ErrBlocked            = errors.New("content blocked")
)
