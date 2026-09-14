// Run: go run examples/go/main.go
package main

import (
	"log/slog"

	"github.com/sanprojects/unilog"
	_ "github.com/sanprojects/unilog/auto"
)

func main() {
	defer unilog.Recover()
	slog.Info("Subscription updated")
	slog.Error("User not found", "id", 123)
	panic("unhandled — watch this become a FATAL record, then crash normally")
}
