package detect

var disposableDomains = map[string]struct{}{
	"10minutemail.com":  {},
	"guerrillamail.com": {},
	"mailinator.com":    {},
	"yopmail.com":       {},
	"temp-mail.org":     {},
	"tempmail.email":    {},
	"dispostable.com":   {},
	"sharklasers.com":   {},
	"trashmail.com":     {},
	"getnada.com":       {},
	"maildrop.cc":       {},
	"fakeinbox.com":     {},
	"mintemail.com":     {},
	"spamgourmet.com":   {},
}

var spamProviders = map[string]struct{}{
	"guerrillamail.com": {},
	"mailinator.com":    {},
	"sharklasers.com":   {},
	"spamgourmet.com":   {},
	"trashmail.com":     {},
	"tempmail.email":    {},
}
