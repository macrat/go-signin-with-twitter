package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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

	tok, _ := json.Marshal(accessToken)
	http.SetCookie(w, &http.Cookie{
		Name:  "access_token",
		Value: url.QueryEscape(string(tok)),
		Path:  "/",
	})
	fmt.Println("json", string(tok))
	fmt.Println("query", url.QueryEscape(string(tok)))

	http.Redirect(w, r, "/user_info", http.StatusFound)
}

func UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("access_token")
	raw, _ := url.QueryUnescape(c.Value)
	var token oauth.AccessToken
	json.Unmarshal([]byte(raw), &token)

	resp, err := consumer.Get("https://api.twitter.com/1.1/account/verify_credentials.json", nil, &token)
	if err != nil {
		fmt.Errorf("failed to get account information: %s\n", err.Error())
		fmt.Fprintln(w, "failed to get account information")
		return
	}
	defer resp.Body.Close()

	bytes, _ := ioutil.ReadAll(resp.Body)

	var info struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		ScreenName  string `json:"screen_name"`
		Description string `json:"description"`
		Icon        string `json:"profile_image_url_https"`
	}
	json.Unmarshal(bytes, &info)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<img src=\"%s\"><br>ID: %d<br>Name: %s (@%s)<br>Description:<br>%s",
		info.Icon,
		info.ID,
		info.Name,
		info.ScreenName,
		info.Description,
	)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<a href=\"/user_info\">show user info</a><br><a href=\"/authorize\">sign in with twitter</a>")
	})
	http.HandleFunc("/authorize", AuthorizeHandler)
	http.HandleFunc("/oauth_callback", OauthCallbackHandler)
	http.HandleFunc("/user_info", UserInfoHandler)

	fmt.Errorf("error: %s\n", http.ListenAndServe(":5000", nil))
}
