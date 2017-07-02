//
// main.go
// Copyright (C) 2017 weirdgiraffe <giraffe@cyberzoo.xyz>
//
// Distributed under terms of the MIT license.
//

package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/render"
	"github.com/weirdgiraffe/github"
)

var addr = flag.String("addr", "127.0.0.1:8080", "address to listen on")
var host = flag.String("hostname", "randomuser.cyberzoo.xyz", "callback hostname")

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
	flag.Parse()
	sessions := NewInMemorySessionProvider()
	oauthConf := &oauth2.Config{
		RedirectURL:  "https://" + *host + "/oauth/callback",
		ClientID:     ClientID(),
		ClientSecret: ClientSecret(),
		Scopes:       []string{},
		Endpoint:     githuboauth.Endpoint,
	}

	r := chi.NewRouter()
	r.Route("/", func(r chi.Router) {
		r.Use(middleware.Logger)
		r.Use(middleware.RealIP)
		r.Use(SessionCtx(sessions))
		r.Use(render.SetContentType(render.ContentTypeHTML))

		r.Get("/", handleIndex)

		r.Route("/oauth", func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ctx := context.WithValue(r.Context(), "oauthConf", oauthConf)
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			})
			r.Get("/", handleOAuth)
			r.Get("/callback", handleOAuthCallback)
		})

	})
	log.Printf("run on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, r))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, ok := ctx.Value(SessionCtxKey).(*Session)
	if !ok {
		log.Printf(
			"%s : session is not set",
			ctx.Value(middleware.RequestIDKey),
		)
		http.Error(w, http.StatusText(422), 422)
		return
	}
	render.Status(r, http.StatusOK)
	indexHTML.Execute(w, session)
}

func handleOAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, ok := ctx.Value(SessionCtxKey).(*Session)
	if !ok {
		// unprocessable entry
		log.Printf("OAuth from %s: no session",
			r.RemoteAddr,
		)
		http.Error(w, http.StatusText(422), 422)
		return
	}
	if session.Authorized() {
		log.Printf(
			"OAuth from %s: already authorized as GitHub user '%s'",
			r.RemoteAddr, session.User,
		)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	conf, ok := ctx.Value("oauthConf").(*oauth2.Config)
	if !ok {
		// unprocessable entry
		log.Printf(
			"OAuth from %s: no oauth config",
			r.RemoteAddr,
		)
		http.Error(w, http.StatusText(422), 422)
		return
	}
	url := conf.AuthCodeURL(session.ID, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, ok := ctx.Value(SessionCtxKey).(*Session)
	if !ok {
		// unprocessable entry
		log.Printf(
			"OAuth callback from %s: no session",
			r.RemoteAddr,
		)
		http.Error(w, http.StatusText(422), 422)
		return
	}
	conf, ok := ctx.Value("oauthConf").(*oauth2.Config)
	if !ok {
		// unprocessable entry
		log.Printf(
			"OAuth callback from %s: no oauth config",
			r.RemoteAddr,
		)
		http.Error(w, http.StatusText(422), 422)
		return
	}
	state := r.FormValue("state")
	if state != session.ID {
		log.Printf(
			"OAuth callback from %s: invalid oauth state '%s' !=  '%s'",
			r.RemoteAddr, session.ID, state,
		)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	code := r.FormValue("code")
	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Printf(
			"OAuth callback from %s: oauthConf.Exchange() failed with '%s'",
			r.RemoteAddr, err,
		)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if token.Valid() == false {
		log.Printf(
			"OAuth callback from %s: token is not valid",
			r.RemoteAddr, token.Valid(),
		)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// client is set right from now on
	oauthClient := conf.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	user, err := client.User()
	if err != nil {
		log.Printf(
			"OAuth callback from %s: github.User() failed with '%s'",
			r.RemoteAddr, err,
		)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	log.Printf(
		"OAuth callback from %s: logged in as GitHub user '%s'",
		r.RemoteAddr, user.Login,
	)
	session.User = user.Login
	session.OAuthToken = token
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
