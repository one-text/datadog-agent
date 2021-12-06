package module

import (
	"fmt"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

var l *loader

func init() {
	l = &loader{
		modules: make(map[config.ModuleName]Module),
		errors:  make(map[config.ModuleName]error),
	}
}

// loader is responsible for managing the lifecyle of each api.Module, which includes:
// * Module initialization;
// * Module termination;
// * Module telemetry consolidation;
type loader struct {
	sync.Mutex
	modules map[config.ModuleName]Module
	errors  map[config.ModuleName]error
	stats   map[string]interface{}
	cfg     *config.Config
	router  *Router
	closed  bool
}

// NewModule initialize a new module
func NewModule(cfg *config.Config, factory Factory) (Module, error) {
	// TODO should be removed in profit of IsEnabled
	if !cfg.ModuleIsEnabled(factory.Name) {
		log.Infof("%s module disabled", factory.Name)
		return nil, nil
	}

	module, err := factory.Ctor(cfg)
	if err != nil {
		return nil, err
	}

	if !module.IsEnabled() {
		log.Infof("module `%s` not enabled", factory.Name)
		return nil, nil
	}

	return module, nil
}

// Register a set of modules, which involves:
// * Initialization using the provided Factory;
// * Registering the HTTP endpoints of each module;
func Register(cfg *config.Config, httpMux *mux.Router, module Module) error {
	router := NewRouter(httpMux)


		if err = module.Register(router); err != nil {
			l.errors[factory.Name] = err
			log.Errorf("error registering HTTP endpoints for module `%s` error: %s", factory.Name, err)
			continue
		}

		log.Infof("module: %s started", factory.Name)
	}

	l.router = router
	l.cfg = cfg
	if len(l.modules) == 0 {
		return errors.New("no module could be loaded")
	}

	go updateStats()
	return nil
}

// GetStats returns the stats from all modules, namespaced by their names
func GetStats() map[string]interface{} {
	l.Lock()
	defer l.Unlock()
	return l.stats
}

// RestartModule triggers a module restart
func RestartModule(factory Factory) error {
	l.Lock()
	defer l.Unlock()

	if l.closed {
		return fmt.Errorf("can't restart module because system-probe is shutting down")
	}

	currentModule := l.modules[factory.Name]
	if currentModule == nil {
		return fmt.Errorf("module %s is not running", factory.Name)
	}
	currentModule.Close()

	newModule, err := factory.Ctor(l.cfg)
	if err != nil {
		l.errors[factory.Name] = err
		return err
	}
	delete(l.errors, factory.Name)
	log.Infof("module %s restarted", factory.Name)

	err = newModule.Register(l.router)
	if err != nil {
		return err
	}

	l.modules[factory.Name] = newModule
	return nil
}

// Close each registered module
func Close() {
	l.Lock()
	defer l.Unlock()

	if l.closed {
		return
	}

	l.closed = true
	for _, module := range l.modules {
		module.Close()
	}
}

func updateStats(module Module) {
	start := time.Now()
	then := time.Now()
	ticker := time.NewTicker(10 * time.Second)
	for now := range ticker.C {
		l.Lock()
		if l.closed {
			l.Unlock()
			return
		}

		l.stats = make(map[string]interface{})
		for name, module := range l.modules {
			l.stats[string(name)] = module.GetStats()
		}
		for name, err := range l.errors {
			l.stats[string(name)] = map[string]string{"Error": err.Error()}
		}

		l.stats["updated_at"] = now.Unix()
		l.stats["delta_seconds"] = now.Sub(then).Seconds()
		l.stats["uptime"] = now.Sub(start).String()
		then = now
		l.Unlock()
	}
}
