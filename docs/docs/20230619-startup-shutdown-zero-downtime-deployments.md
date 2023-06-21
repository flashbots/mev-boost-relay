# On graceful service startup and shutdown, and zero-downtime deployments

2023-06-19, by [@metachris](https://twitter.com/metachris), [@0x416e746f6e](https://github.com/0x416e746f6e)

---

This document explains the details of API service startup and shutdown behavior, in particular related to:
- Zero-downtime deployments
- Proposer API
  - Needing data before being able to handle `getPayload` requests (known validators)
  - Draining requests before shutting down

---

## TL;DR

- We've added two endpoints: `/livez` and `/readyz` (per [k8s docs](https://kubernetes.io/docs/reference/using-api/health-checks/)) in [#469](https://github.com/flashbots/mev-boost-relay/pull/469):
- On startup:
    - `/livez` is immediately available and positive, and will stay so until the service is shut down
    - `/readyz` starts negative, until all information is loaded to safely process requests (known validators for the proposer API)
    - Configure your orchestration tooling to route traffic to the service only if and when `/readyz` is positive!
- On shutdown:
    - `/readyz` returns a negative result
    - Wait a little and drain all requests (by default, 30 sec -- make sure your orchestration graceful shutdown period is greater than that (i.e. set to 60 sec))
    - Stop the webserver, and stop the program
- See also: https://kubernetes.io/docs/reference/using-api/health-checks/

---

## Kubernetes background about health-checks

There are three types of health-checks (probes): [k8s docs](https://kubernetes.io/docs/reference/using-api/health-checks/)

1. Startup probe
2. Liveness probe (`/livez`)
3. Readiness probe (`/readyz`)

(All of these can be HTTP requests or commands)

1. startup check:
    - only for the startup phase
    - confirm that pod has started
    - if it fails, k8s will destroy and recreate
2. liveness check:
    - indicated whether the service is alive. if `false`, then k8s should destroy & recreate the pods
    - based on rules, timeouts, etc
    - status exposed via `/livez`
3. readiness check:
    - Applications may be temporarily unable to serve traffic.
    - An application might need to load large data or configuration files during startup or depend on external services after startup.
    - In such cases, you don't want to kill the application, but you don't want to send it requests either.
    - https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-readiness-probes
    - status exposed via `/readyz`
    - if that is `false`, then k8s will stop sending traffic to that pod but doesn't touch it otherwise

---

## API Startup + Shutdown Sequence

The proposer API needs to load all known validators before serving traffic, otherwise, there's a risk of missed slots due to `getPayload` not having all the information it needs to succeed.

**Correct startup sequence:**
1. Service starts
2. Does minimal initial checks
3. Starts HTTP server (`live=true`, `ready=false`)
4. Updates known validators from CL client (can take 10-30 sec)
5. Sets `ready=true`, and starts receiving traffic

At this point, the pod is operational and can service traffic.

**Correct shutdown sequence:**

1. Shutdown initiated (through signals `syscall.SIGINT` or `syscall.SIGTERM`)
2. Set `ready=false` to stop receiving new traffic
3. Wait some time
4. Drain pending requests
5. Shut down (setting `live=false` is not necessary anymore)


---

## Example k8s + AWS configuration

```yaml
 metadata:
   name: boost-relay-api-proposer
   annotations:
     alb.ingress.kubernetes.io/healthcheck-interval-seconds: "10"
     alb.ingress.kubernetes.io/healthcheck-path: /readyz
     alb.ingress.kubernetes.io/healthcheck-port: "8080"
 spec:
  template:
    spec:
      terminationGracePeriodSeconds: 60
      containers:
        - name: boost-relay-api-proposer
          livenessProbe:
            initialDelaySeconds: 5
            failureThreshold: 2
            httpGet:
              path: /livez
              port: 8080
          readinessProbe:
            initialDelaySeconds: 5
            failureThreshold: 2
            httpGet:
              path: /readyz
              port: 8080
```

---

## See also

- https://kubernetes.io/docs/reference/using-api/health-checks/
- https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
- https://komodor.com/blog/kubernetes-health-checks-everything-you-need-to-know/
- https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.2/guide/ingress/annotations/
