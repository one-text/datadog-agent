package testutil

import (
	"context"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	testConfig = `
<seelog type="sync">
	<outputs formatid="main">
		<console/>
	</outputs>
	<formats>
		<format id="main" format="%NAME %Msg%n"/>
	</formats>
</seelog>`
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

type LogFinder struct {
	pattern    *regexp.Regexp
	logChannel chan string
	enabled    bool
}

func (l *LogFinder) callback(_ string) seelog.FormatterFunc {
	return func(message string, _ seelog.LogLevel, _ seelog.LogContextInterface) interface{} {
		if l.enabled && l.pattern.MatchString(message) {
			l.logChannel <- message
		}
		return ""
	}
}

func SetupLogScanner(ctx context.Context, pattern *regexp.Regexp, logChannel chan string, logLevel string) error {
	logFinder := LogFinder{
		pattern:    pattern,
		logChannel: logChannel,
		enabled:    true,
	}
	go func() {
		<-ctx.Done()
		logFinder.enabled = false
	}()

	// We cannot register the same formatter twice, or to unregister. Instead, I'm creating a random name for the
	// formatter. The formatter name must be unique.
	customFormatterName := "Scanner" + RandStringRunes(5)
	if err := seelog.RegisterCustomFormatter(customFormatterName, logFinder.callback); err != nil {
		return err
	}
	config := strings.Replace(testConfig, "NAME", customFormatterName, -1)
	logger, err := seelog.LoggerFromConfigAsString(config)
	if err != nil {
		return err
	}
	log.SetupLogger(logger, logLevel)
	return nil
}
