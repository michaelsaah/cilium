// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// DefaultPrometheusNamespace is the default namespace (prefix) used
	// for all Hubble related Prometheus metrics
	DefaultPrometheusNamespace = "hubble"
)

// Map is a set of metrics with their corresponding options
type Map map[string]Options

// ParseMetricList parses a slice of metric options and returns a map of
// enabled metrics
func ParseMetricList(enabledMetrics []string) (m Map) {
	m = Map{}
	for _, metric := range enabledMetrics {
		s := strings.SplitN(metric, ":", 2)
		if len(s) == 2 {
			m[s[0]] = ParseOptions(s[1])
		} else {
			m[s[0]] = Options{}
		}
	}
	return
}

// Handlers contains all the metrics handlers.
type Handlers struct {
	handlers       []Handler
	flowProcessors []FlowProcessor
}

// Plugin is a metric plugin. A metric plugin is associated a name and is
// responsible to spawn metric handlers of a certain type.
type Plugin interface {
	// NewHandler returns a new metric handler of the respective plugin
	NewHandler() Handler

	// HelpText returns a human readable help text including a description
	// of the options
	HelpText() string
}

// Handler is a basic metric handler.
type Handler interface {
	// Init must initialize the metric handler by validating and parsing
	// the options and then registering all required metrics with the
	// specifies Prometheus registry
	Init(registry *prometheus.Registry, options Options) error

	// Status returns the configuration status of the metric handler
	Status() string
}

// FlowProcessor is a metric handler which requires flows to perform metrics
// accounting.
// It is called upon receival of raw event data and is responsible
// to perform metrics accounting according to the scope of the metrics plugin.
type FlowProcessor interface {
	// ProcessFlow must processes a flow event and perform metrics
	// accounting
	ProcessFlow(ctx context.Context, flow *pb.Flow)
}

func NewHandlers(log logrus.FieldLogger, registry *prometheus.Registry, in []NamedHandler) (*Handlers, error) {
	var handlers Handlers
	for _, item := range in {
		handlers.handlers = append(handlers.handlers, item.Handler)
		if fp, ok := item.Handler.(FlowProcessor); ok {
			handlers.flowProcessors = append(handlers.flowProcessors, fp)
		}

		if err := item.Handler.Init(registry, item.Options); err != nil {
			return nil, fmt.Errorf("unable to initialize metric '%s': %s", item.Name, err)
		}

		log.WithFields(logrus.Fields{"name": item.Name, "status": item.Handler.Status()}).Info("Configured metrics plugin")
	}
	return &handlers, nil
}

// ProcessFlow processes a flow by calling ProcessFlow it on to all enabled
// metric handlers
func (h Handlers) ProcessFlow(ctx context.Context, flow *pb.Flow) {
	for _, fp := range h.flowProcessors {
		fp.ProcessFlow(ctx, flow)
	}
}

var registry = NewRegistry(
	logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble"),
)

// DefaultRegistry returns the default registry of all available metric plugins
func DefaultRegistry() *Registry {
	return registry
}
