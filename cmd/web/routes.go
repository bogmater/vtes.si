package main

import (
	"net/http"

	"github.com/bogmater/vtes.si/assets"

	"github.com/go-chi/chi/v5"
)

func (app *application) routes() http.Handler {
	mux := chi.NewRouter()
	mux.NotFound(app.notFound)

	mux.Use(app.logAccess)
	mux.Use(app.recoverPanic)
	mux.Use(app.securityHeaders)

	fileServer := http.FileServer(http.FS(assets.EmbeddedFiles))
	mux.Handle("/static/*", fileServer)

	mux.Group(func(mux chi.Router) {
		mux.Use(app.requireBasicAuthentication)

		mux.Get("/basic-auth-protected", app.protected)
	})

	mux.Group(func(mux chi.Router) {
		mux.Use(app.preventCSRF)
		mux.Use(app.authenticate)

		mux.Get("/", app.home)

		mux.Group(func(mux chi.Router) {
			mux.Use(app.requireAnonymousUser)

			mux.Get("/signup", app.signup)
			mux.Post("/signup", app.signup)
			mux.Get("/login", app.login)
			mux.Post("/login", app.login)
			mux.Get("/forgotten-password", app.forgottenPassword)
			mux.Post("/forgotten-password", app.forgottenPassword)
			mux.Get("/forgotten-password-confirmation", app.forgottenPasswordConfirmation)
			mux.Get("/password-reset/{plaintextToken}", app.passwordReset)
			mux.Post("/password-reset/{plaintextToken}", app.passwordReset)
			mux.Get("/password-reset-confirmation", app.passwordResetConfirmation)
		})

		mux.Group(func(mux chi.Router) {
			mux.Use(app.requireAuthenticatedUser)

			mux.Post("/logout", app.logout)
		})
	})

	return mux
}
