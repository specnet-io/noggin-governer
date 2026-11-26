// noggin-governer: administrative controls for noggin (approval of registrations,
// group requests and management of the groups they create). See README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/specnet-io/noggin-governer/internal/config"
	"github.com/specnet-io/noggin-governer/internal/ipa"
	"github.com/specnet-io/noggin-governer/internal/mail"
	"github.com/specnet-io/noggin-governer/internal/store"
	"github.com/specnet-io/noggin-governer/internal/web"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck": // for HEALTHCHECK / podman HealthCmd in a scratch image
			os.Exit(healthcheck())
		case "version", "--version", "-v":
			fmt.Println(version)
			return
		}
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	slog.Info("starting", "version", version, "noggin_config", cfg.NogginConfigPath, "noggin_config_found", cfg.NogginFound,
		"ipa_servers", cfg.IPAServers, "ipa_user", cfg.IPAUser, "approver_group", cfg.ApproverGroup,
		"manager_group", cfg.ManagerGroup, "container_group", cfg.ContainerGroup, "mail", cfg.MailEnabled)
	for _, w := range cfg.Warnings {
		slog.Warn("config", "warning", w)
	}

	ic, err := ipa.New(ipa.Options{Servers: cfg.IPAServers, CACertFile: cfg.IPACACert, User: cfg.IPAUser, Password: cfg.IPAPassword})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.json"))
	if err != nil {
		return err
	}
	srv, err := web.New(cfg, ic, st, mail.New(cfg.MailServer, cfg.MailPort, cfg.MailFrom, cfg.MailEnabled), version)
	if err != nil {
		return err
	}

	servers := []*http.Server{
		{Addr: cfg.Listen, Handler: srv.UIHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute},
		{Addr: cfg.HookListen, Handler: srv.HookHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second},
	}
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			slog.Info("listening", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(s)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(sctx)
	}
	return nil
}

func healthcheck() int {
	addr := os.Getenv("GOVERNER_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(strings.Trim(host, "[]"), port) + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
