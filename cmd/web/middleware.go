package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bogmater/vtes.si/internal/response"

	"github.com/justinas/nosurf"
	"github.com/tomasen/realip"
	"golang.org/x/crypto/bcrypt"
)

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			err := recover()
			if err != nil {
				app.serverError(w, r, fmt.Errorf("%s", err))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func (app *application) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "deny")

		next.ServeHTTP(w, r)
	})
}

func (app *application) logAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mw := response.NewMetricsResponseWriter(w)
		next.ServeHTTP(mw, r)

		var (
			ip     = realip.FromRequest(r)
			method = r.Method
			url    = r.URL.String()
			proto  = r.Proto
		)

		userAttrs := slog.Group("user", "ip", ip)
		requestAttrs := slog.Group("request", "method", method, "url", url, "proto", proto)
		responseAttrs := slog.Group("repsonse", "status", mw.StatusCode, "size", mw.BytesCount)

		app.logger.Info("access", userAttrs, requestAttrs, responseAttrs)
	})
}

func (app *application) preventCSRF(next http.Handler) http.Handler {
	csrfHandler := nosurf.New(next)

	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		MaxAge:   86400,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	})

	return csrfHandler
}

func (app *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := app.sessionStore.Get(r, "session")
		if err != nil {
			app.serverError(w, r, err)
			return
		}

		userID, ok := session.Values["userID"].(int)
		if ok {
			user, found, err := app.db.GetUser(userID)
			if err != nil {
				app.serverError(w, r, err)
				return
			}

			if found {
				r = contextSetAuthenticatedUser(r, user)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (app *application) requireAuthenticatedUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticatedUser := contextGetAuthenticatedUser(r)

		if authenticatedUser == nil {
			session, err := app.sessionStore.Get(r, "session")
			if err != nil {
				app.serverError(w, r, err)
				return
			}

			session.Values["redirectPathAfterLogin"] = r.URL.Path

			err = session.Save(r, w)
			if err != nil {
				app.serverError(w, r, err)
				return
			}

			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		w.Header().Add("Cache-Control", "no-store")

		next.ServeHTTP(w, r)
	})
}

func (app *application) requireAnonymousUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticatedUser := contextGetAuthenticatedUser(r)

		if authenticatedUser != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return

		}

		next.ServeHTTP(w, r)
	})
}

func (app *application) requireBasicAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, plaintextPassword, ok := r.BasicAuth()
		if !ok {
			app.basicAuthenticationRequired(w, r)
			return
		}

		if app.config.basicAuth.username != username {
			app.basicAuthenticationRequired(w, r)
			return
		}

		err := bcrypt.CompareHashAndPassword(
			[]byte(app.config.basicAuth.hashedPassword),
			[]byte(plaintextPassword),
		)
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			app.basicAuthenticationRequired(w, r)
			return
		case err != nil:
			app.serverError(w, r, err)
			return
		}

		next.ServeHTTP(w, r)
	})
}
