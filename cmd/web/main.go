package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sync"

	"github.com/bogmater/vtes.si/internal/database"
	"github.com/bogmater/vtes.si/internal/env"
	"github.com/bogmater/vtes.si/internal/smtp"
	"github.com/bogmater/vtes.si/internal/version"

	"github.com/gorilla/sessions"
	"github.com/lmittmann/tint"

	_ "github.com/joho/godotenv/autoload"
)

func main() {
	logger := slog.New(tint.NewHandler(os.Stdout, &tint.Options{Level: slog.LevelDebug}))

	err := run(logger)
	if err != nil {
		trace := string(debug.Stack())
		logger.Error(err.Error(), "trace", trace)
		os.Exit(1)
	}
}

type config struct {
	baseURL   string
	httpPort  int
	basicAuth struct {
		username       string
		hashedPassword string
	}
	autoHTTPS struct {
		domain  string
		email   string
		staging bool
	}
	cookie struct {
		secretKey string
	}
	db struct {
		dsn         string
		automigrate bool
	}
	notifications struct {
		email string
	}
	session struct {
		secretKey    string
		oldSecretKey string
	}
	smtp struct {
		host     string
		port     int
		username string
		password string
		from     string
	}
}

type application struct {
	config       config
	db           *database.DB
	logger       *slog.Logger
	mailer       *smtp.Mailer
	sessionStore *sessions.CookieStore
	wg           sync.WaitGroup
}

func run(logger *slog.Logger) error {
	var cfg config

	cfg.baseURL = env.GetString("BASE_URL", "http://localhost:4444")
	cfg.httpPort = env.GetInt("HTTP_PORT", 4444)
	cfg.autoHTTPS.domain = env.GetString("AUTO_HTTPS_DOMAIN", "")
	cfg.autoHTTPS.email = env.GetString("AUTO_HTTPS_EMAIL", "admin@example.com")
	cfg.autoHTTPS.staging = env.GetBool("AUTO_HTTPS_STAGING", false)
	cfg.basicAuth.username = env.GetString("BASIC_AUTH_USERNAME", "admin")
	cfg.basicAuth.hashedPassword = env.GetString(
		"BASIC_AUTH_HASHED_PASSWORD",
		"$2a$10$jRb2qniNcoCyQM23T59RfeEQUbgdAXfR6S0scynmKfJa5Gj3arGJa",
	)
	cfg.cookie.secretKey = env.GetString("COOKIE_SECRET_KEY", "5suznfgms4ibxfrga3ozimiallbmolzd")
	cfg.db.dsn = env.GetString("DB_DSN", "user:pass@localhost:5432/db")
	cfg.db.automigrate = env.GetBool("DB_AUTOMIGRATE", true)
	cfg.notifications.email = env.GetString("NOTIFICATIONS_EMAIL", "")
	cfg.session.secretKey = env.GetString("SESSION_SECRET_KEY", "5owh22sr3c3keobeqgmh67vujkkelm5j")
	cfg.session.oldSecretKey = env.GetString("SESSION_OLD_SECRET_KEY", "")
	cfg.smtp.host = env.GetString("SMTP_HOST", "example.smtp.host")
	cfg.smtp.port = env.GetInt("SMTP_PORT", 25)
	cfg.smtp.username = env.GetString("SMTP_USERNAME", "example_username")
	cfg.smtp.password = env.GetString("SMTP_PASSWORD", "pa55word")
	cfg.smtp.from = env.GetString("SMTP_FROM", "Example Name <no_reply@example.org>")

	showVersion := flag.Bool("version", false, "display version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("version: %s\n", version.Get())
		return nil
	}

	logger.Debug(cfg.db.dsn)

	db, err := database.New(cfg.db.dsn, cfg.db.automigrate)
	if err != nil {
		return err
	}
	defer db.Close()

	mailer, err := smtp.NewMailer(
		cfg.smtp.host,
		cfg.smtp.port,
		cfg.smtp.username,
		cfg.smtp.password,
		cfg.smtp.from,
	)
	if err != nil {
		return err
	}

	keyPairs := [][]byte{[]byte(cfg.session.secretKey), nil}
	if cfg.session.oldSecretKey != "" {
		keyPairs = append(keyPairs, []byte(cfg.session.oldSecretKey), nil)
	}

	sessionStore := sessions.NewCookieStore(keyPairs...)
	sessionStore.Options = &sessions.Options{
		HttpOnly: true,
		MaxAge:   86400 * 7,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	}

	app := &application{
		config:       cfg,
		db:           db,
		logger:       logger,
		mailer:       mailer,
		sessionStore: sessionStore,
	}

	if cfg.autoHTTPS.domain != "" {
		return app.serveAutoHTTPS()
	}

	return app.serveHTTP()
}
