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

	GetHeaderLatencyHistogram    otelapi.Float64Histogram
	GetPayloadLatencyHistogram   otelapi.Float64Histogram
	PublishBlockLatencyHistogram otelapi.Float64Histogram

	SubmitNewBlockLatencyHistogram           otelapi.Float64Histogram
	SubmitNewBlockReadLatencyHistogram       otelapi.Float64Histogram
	SubmitNewBlockDecodeLatencyHistogram     otelapi.Float64Histogram
	SubmitNewBlockPrechecksLatencyHistogram  otelapi.Float64Histogram
	SubmitNewBlockSimulationLatencyHistogram otelapi.Float64Histogram
	SubmitNewBlockRedisLatencyHistogram      otelapi.Float64Histogram

	SubmitNewBlockRedisPayloadLatencyHistogram otelapi.Float64Histogram
	SubmitNewBlockRedisTopBidLatencyHistogram  otelapi.Float64Histogram
	SubmitNewBlockRedisFloorLatencyHistogram   otelapi.Float64Histogram

	BuilderDemotionCount otelapi.Int64Counter

	// latencyBoundariesMs is the set of buckets of exponentially growing
	// latencies that are ranging from 5ms up to 12s
	latencyBoundariesMs = otelapi.WithExplicitBucketBoundaries(func() []float64 {
		base := math.Exp(math.Log(12.0) / 15.0)
		res := make([]float64, 0, 48)
		for i := -31; i < 16; i++ {
			res = append(res,
				1000.0*math.Pow(base, float64(i)),
			)
		}
		return res
	}()...)
)

func Setup(ctx context.Context) error {
	for _, setup := range []func(context.Context) error{
		setupMeter, // must come first
		setupGetHeaderLatency,
		setupGetPayloadLatency,
		setupPublishBlockLatency,
		setupSubmitNewBlockLatency,
		setupSubmitNewBlockReadLatency,
		setupSubmitNewBlockDecodeLatency,
		setupSubmitNewBlockPrechecksLatency,
		setupSubmitNewBlockSimulationLatency,
		setupSubmitNewBlockRedisLatency,
		setupSubmitNewBlockRedisPayloadLatency,
		setupSubmitNewBlockRedisTopBidLatency,
		setupSubmitNewBlockRedisFloorLatency,
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

func setupGetHeaderLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"get_header_latency",
		otelapi.WithDescription("statistics on the duration of getHeader requests execution"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	GetHeaderLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupGetPayloadLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"get_payload_latency",
		otelapi.WithDescription("statistics on the duration of getPayload requests execution"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	GetPayloadLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupPublishBlockLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"publish_block_latency",
		otelapi.WithDescription("statistics on the duration of publishBlock requests sent to beacon node"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	PublishBlockLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_latency",
		otelapi.WithDescription("statistics on the duration of submitNewBlock requests execution"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockReadLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_read_latency",
		otelapi.WithDescription("statistics on the duration of reading the payload of submitNewBlock requests"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockReadLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockDecodeLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_decode_latency",
		otelapi.WithDescription("statistics on the duration of decoding the payload of submitNewBlock requests"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockDecodeLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockPrechecksLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_prechecks_latency",
		otelapi.WithDescription("statistics on the duration of prechecks (floor bid, signature etc.) of submitNewBlock requests"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockPrechecksLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockSimulationLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_simulation_latency",
		otelapi.WithDescription("statistics on the block simulation duration of submitNewBlock requests"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockSimulationLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockRedisLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_redis_latency",
		otelapi.WithDescription("statistics on the redis update duration of submitNewBlock requests"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockRedisLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockRedisPayloadLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_redis_payload_latency",
		otelapi.WithDescription("statistics on the redis save payload duration during redis updates of submitNewBlock requests"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockRedisPayloadLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockRedisTopBidLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_redis_top_bid_latency",
		otelapi.WithDescription("statistics on the redis update top bid duration during redis updates of submitNewBlock requests"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockRedisTopBidLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupSubmitNewBlockRedisFloorLatency(_ context.Context) error {
	latency, err := meter.Float64Histogram(
		"submit_new_block_redis_floor_latency",
		otelapi.WithDescription("statistics on the redis update floor bid duration during redis updates of submitNewBlock requests"),
		otelapi.WithUnit("ms"),
		latencyBoundariesMs,
	)
	SubmitNewBlockRedisFloorLatencyHistogram = latency
	if err != nil {
		return err
	}
	return nil
}

func setupBuilderDemotionCount(_ context.Context) error {
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
