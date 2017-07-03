//
// main.go
// Copyright (C) 2017 weirdgiraffe <giraffe@cyberzoo.xyz>
//
// Distributed under terms of the MIT license.
//

package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/render"
)

var addr = flag.String("addr", "127.0.0.1:8080", "address to listen on")

func main() {
	flag.Parse()
	sessions := NewInMemorySessionProvider()

	r := chi.NewRouter()
	r.Route("/", func(r chi.Router) {
		r.Use(middleware.RealIP)
		r.Use(middleware.Logger)
		r.Use(SessionCtx(sessions))
		r.Use(render.SetContentType(render.ContentTypeHTML))

		r.Get("/", handleIndex)
		r.Route(OAuthPath, OAuth{}.Routes)

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
	if session.Authorized() {
		log.Printf("token:\n%s", session.TokenJSON())
	}
	render.Status(r, http.StatusOK)
	indexHTML.Execute(w, session)
}
