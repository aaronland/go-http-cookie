package cookie

import (
	"context"
	"errors"
	"github.com/aaronland/go-secretbox"
	"github.com/awnumar/memguard"
	"net/http"
	"net/url"
)

func init() {
	ctx := context.Background()
	RegisterCookie(ctx, "encrypted", NewEncryptedCookie)

	memguard.CatchInterrupt()
}

type EncryptedCookie struct {
	Cookie
	name   string
	secret *memguard.Enclave
	salt   string
}

func NewEncryptedCookie(ctx context.Context, uri string) (Cookie, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	q := u.Query()

	name := q.Get("name")
	secret := q.Get("secret")
	salt := q.Get("salt")

	if name == "" {
		return nil, errors.New("Missing name")
	}

	if secret == "" {
		return nil, errors.New("Missing secret")
	}

	if salt == "" {
		return nil, errors.New("Missing salt")
	}

	secret_key := memguard.NewEnclave([]byte(secret))

	c := EncryptedCookie{
		name:   name,
		secret: secret_key,
		salt:   salt,
	}

	return &c, nil
}

func (c *EncryptedCookie) Get(req *http.Request) (string, error) {

	http_cookie, err := req.Cookie(c.name)

	if err != nil {
		return "", err
	}

	opts := secretbox.NewSecretboxOptions()
	opts.Salt = c.salt

	sb, err := secretbox.NewSecretboxWithEnclave(c.secret, opts)

	if err != nil {
		return "", err
	}

	unlocked, err := sb.Unlock(http_cookie.Value)

	if err != nil {
		return "", err
	}

	defer unlocked.Destroy()
	return unlocked.String(), nil
}

func (c *EncryptedCookie) Set(rsp http.ResponseWriter, body string) error {

	http_cookie := &http.Cookie{
		Value: body,
	}

	return c.SetCookie(rsp, http_cookie)
}

func (c *EncryptedCookie) SetCookie(rsp http.ResponseWriter, http_cookie *http.Cookie) error {

	if http_cookie.Name != "" {
		return errors.New("Cookie name already set")
	}

	body := http_cookie.Value

	opts := secretbox.NewSecretboxOptions()
	opts.Salt = c.salt

	secret, err := c.secret.Open()

	if err != nil {
		return err
	}

	defer secret.Destroy()

	sb, err := secretbox.NewSecretbox(secret.String(), opts)

	if err != nil {
		return err
	}

	enc, err := sb.Lock([]byte(body))

	if err != nil {
		return err
	}

	http_cookie.Name = c.name
	http_cookie.Value = enc

	http.SetCookie(rsp, http_cookie)
	return nil
}

func (c *EncryptedCookie) Delete(rsp http.ResponseWriter) error {

	http_cookie := http.Cookie{
		Name:   c.name,
		Value:  "",
		MaxAge: -1,
	}

	http.SetCookie(rsp, &http_cookie)
	return nil
}
