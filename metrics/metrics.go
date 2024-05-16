// Package metrics provides prometheus metrics primitives to the rest of the app
package metrics

import (
	"context"
	"math"

	"go.opentelemetry.io/otel/exporters/prometheus"
	otelapi "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

const (
	metricsNamespace = "mev-boost-relay"
)

var (
	meter otelapi.Meter

	GetPayloadLatencyHistogram   otelapi.Float64Histogram
	PublishBlockLatencyHistogram otelapi.Float64Histogram

	BuilderDemotionCount otelapi.Int64Counter

	latencyBoundaries = otelapi.WithExplicitBucketBoundaries(func() []float64 {
		base := math.Exp(math.Log(12.0) / 15.0)
		res := make([]float64, 0, 31)
		for i := -15; i < 16; i++ {
			res = append(res, math.Pow(base, float64(i)))
		}
		return res
	}()...)
)

func Setup(ctx context.Context) error {
	for _, setup := range []func(context.Context) error{
		setupMeter, // must come first
		setupGetPayloadLatency,
		setupPublishBlockLatency,
		setupBuilderDemotionCount,
	} {
		if err := setup(ctx); err != nil {
			return err
		}
	}

	return nil
}

func setupMeter(ctx context.Context) error {
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(metricsNamespace)),
	)
	if err != nil {
		return err
	}

	exporter, err := prometheus.New(
		prometheus.WithNamespace(metricsNamespace),
	)
	if err != nil {
		return err
	}

	provider := metric.NewMeterProvider(
		metric.WithReader(exporter),
		metric.WithResource(res),
	)

	meter = provider.Meter(metricsNamespace)

	return nil
}

func setupGetPayloadLatency(ctx context.Context) error {
	latency, err := meter.Float64Histogram(
		"get_payload_latency",
		otelapi.WithDescription("statistics on the duration of getPayload requests execution"),
		otelapi.WithUnit("ms"),
		latencyBoundaries,
	)
	GetPayloadLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupPublishBlockLatency(ctx context.Context) error {
	latency, err := meter.Float64Histogram(
		"publish_block_latency",
		otelapi.WithDescription("statistics on the duration of publishBlock requests sent to beacon node"),
		otelapi.WithUnit("ms"),
		latencyBoundaries,
	)
	PublishBlockLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupBuilderDemotionCount(ctx context.Context) error {
	counter, err := meter.Int64Counter(
		"builder_demotion_count",
		otelapi.WithDescription("number of times a builder has been demoted"),
	)
	BuilderDemotionCount = counter
	if err != nil {
		return err
	}
	return nil
}
