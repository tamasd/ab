package auth

// Container struct for OAuth credentials.
type OAuthCredentials struct {
	ID     string
	Secret string
}

func (c OAuthCredentials) Empty() bool {
	return c.ID == "" || c.Secret == ""
}

type OAuthProvider interface {
	GetName() string  // machine name of the provider (usually a lowercase word, max 32 characters)
	GetLabel() string // the name of the OAuth provider that is displayed for the user
}
