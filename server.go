package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/mrjones/oauth"
)

var consumer = oauth.NewConsumer(
	os.Getenv("TWITTER_KEY"),
	os.Getenv("TWITTER_SECRET"),
	oauth.ServiceProvider{
		RequestTokenUrl:   "https://api.twitter.com/oauth/request_token",
		AuthorizeTokenUrl: "https://api.twitter.com/oauth/authorize",
		AccessTokenUrl:    "https://api.twitter.com/oauth/access_token",
	},
)

func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	tokenUrl := fmt.Sprintf("http://%s/oauth_callback", r.Host)
	token, requestUrl, err := consumer.GetRequestTokenAndUrl(tokenUrl)
	if err != nil {
		fmt.Errorf("failed get token: %s\n", err.Error())
		fmt.Fprintln(w, "failed get token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: token.Token,
		Path:  "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "secret",
		Value: token.Secret,
		Path:  "/",
	})

	http.Redirect(w, r, requestUrl, http.StatusFound)
}

func OauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	token, _ := r.Cookie("token")
	secret, _ := r.Cookie("secret")

	if r.URL.Query().Get("oauth_token") != token.Value {
		fmt.Errorf("invalid token\n")
		fmt.Fprintln(w, "invalid token")
		return
	}

	accessToken, err := consumer.AuthorizeToken(
		&oauth.RequestToken{token.Value, secret.Value},
		r.URL.Query().Get("oauth_verifier"),
	)
	if err != nil {
		fmt.Errorf("failed to get access token: %s\n", err.Error())
		fmt.Fprintln(w, "failed to get access token")
		return
	}
	fmt.Println(accessToken)
	fmt.Fprintln(w, "got access token")
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<a href=\"/authorize\">sign in with twitter</a>")
	})
	http.HandleFunc("/authorize", AuthorizeHandler)
	http.HandleFunc("/oauth_callback", OauthCallbackHandler)

	fmt.Errorf("error: %s\n", http.ListenAndServe(":5000", nil))
}
