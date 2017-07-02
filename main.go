//
// main.go
// Copyright (C) 2017 weirdgiraffe <giraffe@cyberzoo.xyz>
//
// Distributed under terms of the MIT license.
//

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"

	"github.com/go-chi/chi"
	"github.com/weirdgiraffe/github"
)

var addr = flag.String("addr", "http://127.0.0.1:8080", "host to work on")
var host = flag.String("callback", "https://5416ee9d.ngrok.io", "callback host")

func ClientID() string {
	if id := os.Getenv("GITHUB_CLIENT_ID"); id != "" {
		return id
	}
	panic("env GITHUB_CLIENT_ID is not set")
}

func ClientSecret() string {
	if secret := os.Getenv("GITHUB_CLIENT_SECRET"); secret != "" {
		return secret
	}
	panic("env GITHUB_CLIENT_SECRET is not set")
}

func main() {
	oauthConf := &oauth2.Config{
		RedirectURL:  *host + "/github_oauth_cb",
		ClientID:     ClientID(),
		ClientSecret: ClientSecret(),
		Scopes:       []string{},
		Endpoint:     githuboauth.Endpoint,
	}
	oauthStateString := "thisshouldberandom"

	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Index Accept from %s", r.Host)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(indexHTML))
	})

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Login Accept from %s", r.Host)
		url := oauthConf.AuthCodeURL(oauthStateString, oauth2.AccessTypeOnline)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	r.Get("/github_oauth_cb", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Auth Accept from %s", r.Host)
		state := r.FormValue("state")
		if state != oauthStateString {
			fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		code := r.FormValue("code")
		token, err := oauthConf.Exchange(oauth2.NoContext, code)
		if err != nil {
			fmt.Printf("oauthConf.Exchange() failed with '%s'\n", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		oauthClient := oauthConf.Client(oauth2.NoContext, token)
		client := github.NewClient(oauthClient)
		// client is set right from now on
		user, err := client.User()
		if err != nil {
			fmt.Printf("client.Users.Get() faled with '%s'\n", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		fmt.Printf("Logged in as GitHub user: %s\n", user.Login)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})

	log.Printf("Started running on %s", *addr)
	host, _ := url.Parse(*addr)
	log.Println(http.ListenAndServe(host.Hostname()+":"+host.Port(), r))
}
