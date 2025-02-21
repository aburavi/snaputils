package utils

import (
	"time"

	"github.com/go-kit/kit/metrics"
)

func NewMetrics(requestCount metrics.Counter,
	requestLatency metrics.Histogram,
	httpDuration metrics.Histogram) MetricsMiddleware {
	return MetricsMiddleware{
		RequestCount:   requestCount,
		RequestLatency: requestLatency,
		HttpDuration:   httpDuration,
	}
}

// Make a new type and wrap into Service interface
// Add expected metrics property to this type
type MetricsMiddleware struct {
	RequestCount   metrics.Counter
	RequestLatency metrics.Histogram
	HttpDuration   metrics.Histogram
}

// Implement service functions and add label method for our metrics
func (midw MetricsMiddleware) MetricsRequestLatency(name string) bool {
	defer func(begin time.Time) {
		lvs := []string{"method", name}
		midw.RequestCount.With(lvs...).Add(1)
		midw.RequestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return true
}

// Implement service functions and add label method for our metrics
func (midw MetricsMiddleware) MetricsHttpDuration(name string) bool {
	defer func(begin time.Time) {
		lvs := []string{"method", name}
		midw.RequestCount.With(lvs...).Add(1)
		midw.HttpDuration.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return true
}
