package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/trafficstars/docker-visor/visor"
)

func init() {
	var formatter log.Formatter = &log.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05 MST",
	}

	if log.IsTerminal() {
		formatter = &log.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05 MST",
		}
	}

	log.SetLevel(log.InfoLevel)
	if b, _ := strconv.ParseBool(os.Getenv("DEBUG")); b {
		log.SetLevel(log.DebugLevel)

		go func() {
			log.Println(http.ListenAndServe(":6060", nil))
		}()
	}

	log.SetFormatter(formatter)
}

func main() {
	visor.Run()
}
