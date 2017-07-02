//
// session.go
// Copyright (C) 2017 weirdgiraffe <giraffe@cyberzoo.xyz>
//
// Distributed under terms of the MIT license.
//

package main

import (
	"context"
	"encoding/base64"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const SessionIdLen = 32
const SessionCtxKey = "session"

type Session struct {
	ID         string
	Expires    time.Time
	OAuthToken *oauth2.Token
	User       string
}

func (s *Session) Authorized() bool {
	if s.User == "" || s.OAuthToken == nil {
		return false
	}
	return s.OAuthToken.Valid()
}

type SessionProvider interface {
	CookieName() string
	GetSession(id string) *Session
	NewSession() *Session
}

func SessionCtx(p SessionProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var s *Session
			if c, err := r.Cookie(p.CookieName()); err == nil {
				s = p.GetSession(c.Value)
			}
			if s == nil {
				s = p.NewSession()
				log.Printf("New session: '%s'", s.ID)
			} else {
				log.Printf("Old session: '%s'", s.ID)
			}
			c := &http.Cookie{
				Name:     p.CookieName(),
				Value:    s.ID,
				HttpOnly: true,
				Path:     "/",
				Expires:  s.Expires,
				MaxAge:   int(time.Until(s.Expires).Seconds()),
			}
			http.SetCookie(w, c)
			ctx := context.WithValue(r.Context(), SessionCtxKey, s)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type InMemorySessionProvider struct {
	mxSession   sync.Mutex
	sessionRand *rand.Rand
	session     map[string]*Session
}

func NewInMemorySessionProvider() *InMemorySessionProvider {
	return &InMemorySessionProvider{
		session:     make(map[string]*Session),
		sessionRand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (p *InMemorySessionProvider) CookieName() string {
	return "_session_"
}

func (p *InMemorySessionProvider) GetSession(id string) *Session {
	if id == "" {
		return nil
	}
	if len(id) != SessionIdLen {
		log.Printf("malformed session id: %s", id)
		return nil
	}
	p.mxSession.Lock()
	defer p.mxSession.Unlock()
	if s, ok := p.session[id]; ok {
		if s.Expires.After(time.Now()) {
			s.Expires = time.Now().Add(7 * 24 * time.Hour)
			return s
		}
		log.Printf("delete expired session: %s", id)
		delete(p.session, id)
	}
	return nil
}

func (p *InMemorySessionProvider) NewSession() *Session {
	p.mxSession.Lock()
	defer p.mxSession.Unlock()
	b := make([]byte, (SessionIdLen / 4 * 3))
	p.sessionRand.Read(b)
	s := &Session{
		ID:      base64.StdEncoding.EncodeToString(b),
		Expires: time.Now().Add(7 * 24 * time.Hour),
	}
	p.session[s.ID] = s
	return s
}
