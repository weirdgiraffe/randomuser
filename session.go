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
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const SessionIdLen = 32
const SessionCtxKey = "session"
const SessionCookieName = "_session_"
const MaxSessions = 4096

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
	GetSession(id string) *Session
	NewSession() (*Session, error)
}

func SessionCtx(p SessionProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var s *Session
			if c, err := r.Cookie(SessionCookieName); err == nil {
				s = p.GetSession(c.Value)
			}
			if s == nil {
				s, err := p.NewSession()
				if err != nil {
					log.Printf("SessionCtx: %v", err)
					next.ServeHTTP(w, r)
					return
				}
				log.Printf("New session: '%s'", s.ID)
			} else {
				log.Printf("Old session: '%s'", s.ID)
			}
			c := &http.Cookie{
				Name:     SessionCookieName,
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
	p.cleanup()
	if s, ok := p.session[id]; ok {
		s.Expires = time.Now().Add(7 * 24 * time.Hour)
		return s
	}
	return nil
}

func (p *InMemorySessionProvider) cleanup() {
	l := []string{}
	for id, s := range p.session {
		if s.Expires.Before(time.Now()) {
			l = append(l, id)
		}
	}
	for i := range l {
		log.Printf("delete expired session: %s", l[i])
		delete(p.session, l[i])
	}
}

func (p *InMemorySessionProvider) NewSession() (*Session, error) {
	p.mxSession.Lock()
	defer p.mxSession.Unlock()
	if len(p.session) > MaxSessions {
		return nil, fmt.Errorf("too many sessions")
	}
	b := make([]byte, (SessionIdLen / 4 * 3))
	for {
		p.sessionRand.Read(b)
		s := &Session{
			ID:      base64.StdEncoding.EncodeToString(b),
			Expires: time.Now().Add(7 * 24 * time.Hour),
		}
		if _, ok := p.session[s.ID]; !ok {
			p.session[s.ID] = s
			return s, nil
		}
	}
}
