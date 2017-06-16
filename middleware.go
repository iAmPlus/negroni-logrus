package negronilogrus

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
)

type timer interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

type realClock struct{}

func (rc *realClock) Now() time.Time {
	return time.Now()
}

func (rc *realClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}

// Middleware is a middleware handler that logs the request as it goes in and the response as it goes out.
type Middleware struct {
	// Logger is the log.Logger instance used to log messages with the Logger middleware
	Logger *logrus.Logger
	// Name is the name of the application as recorded in latency metrics
	Name  string
	After func(*logrus.Entry, negroni.ResponseWriter, time.Duration, string, string) *logrus.Entry

	logStarting bool

	clock timer

	// Exclude URLs from logging
	excludeURLs []string
}

// NewMiddleware returns a new *Middleware, yay!
func NewMiddleware() *Middleware {
	return NewCustomMiddleware(logrus.InfoLevel, &logrus.TextFormatter{}, "web")
}

// NewCustomMiddleware builds a *Middleware with the given level and formatter
func NewCustomMiddleware(level logrus.Level, formatter logrus.Formatter, name string) *Middleware {
	log := logrus.New()
	log.Level = level
	log.Formatter = formatter

	return &Middleware{
		Logger: log,
		Name:   name,
		After:  DefaultAfter,

		logStarting: true,
		clock:       &realClock{},
	}
}

// NewMiddlewareFromLogger returns a new *Middleware which writes to a given logrus logger.
func NewMiddlewareFromLogger(logger *logrus.Logger, name string) *Middleware {
	return &Middleware{
		Logger: logger,
		Name:   name,
		After:  DefaultAfter,

		logStarting: true,
		clock:       &realClock{},
	}
}

// SetLogStarting accepts a bool to control the logging of "started handling
// request" prior to passing to the next middleware
func (m *Middleware) SetLogStarting(v bool) {
	m.logStarting = v
}

// ExcludeURL adds a new URL u to be ignored during logging. The URL u is parsed, hence the returned error
func (m *Middleware) ExcludeURL(u string) error {
	if _, err := url.Parse(u); err != nil {
		return err
	}
	m.excludeURLs = append(m.excludeURLs, u)
	return nil
}

// ExcludedURLs returns the list of excluded URLs for this middleware
func (m *Middleware) ExcludedURLs() []string {
	return m.excludeURLs
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if m.After == nil {
		m.After = DefaultAfter
	}

	for _, u := range m.excludeURLs {
		if r.URL.Path == u {
			next(rw, r)
			return
		}
	}

	start := m.clock.Now()

	// Try to get the real IP
	remoteAddr := r.RemoteAddr
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		remoteAddr = realIP
	}

	entry := logrus.NewEntry(m.Logger)

	if reqID := r.Header.Get("X-Request-Id"); reqID != "" {
		entry = entry.WithField("request_id", reqID)
	}

	next(rw, r)

	latency := m.clock.Since(start)
	res := rw.(negroni.ResponseWriter)

	m.After(entry, res, latency, m.Name, remoteAddr).Info("completed handling request")
}

// AfterFunc is the func type used to modify or replace the *logrus.Entry after
// calling the next func in the middleware chain
type AfterFunc func(*logrus.Entry, negroni.ResponseWriter, time.Duration, string, string) *logrus.Entry

// DefaultAfter is the default func assigned to *Middleware.After
func DefaultAfter(entry *logrus.Entry, res negroni.ResponseWriter, latency time.Duration, name string, remoteAddr string) *logrus.Entry {
	return entry.WithFields(logrus.Fields{
		"status":      res.Status(),
		"text_status": http.StatusText(res.Status()),
		"took":        latency,
		"remote":      remoteAddr,
		fmt.Sprintf("measure#%s.latency", name): latency.Nanoseconds(),
	})
}
