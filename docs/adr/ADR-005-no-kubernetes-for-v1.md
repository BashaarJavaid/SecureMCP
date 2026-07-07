# ADR-005 — No Kubernetes for v1

**Status:** Accepted

**Decision:** Deploy on Docker Compose (local/MVP) and AWS ECS Fargate (production), not Kubernetes/EKS.

**Reasoning:** A single stateless proxy service doesn't need Kubernetes's scheduling/autoscaling machinery to demonstrate that the architecture is horizontally scalable — that claim is demonstrated in the deployment diagram in `ARCHITECTURE.md` (multiple stateless replicas behind a load balancer, sharing Redis/Postgres), not by standing up a live cluster. ECS Fargate provides the same "runs in production on real cloud infrastructure" credibility with a fraction of the operational surface area a K8s cluster requires to run and maintain correctly.

**Alternatives considered:** EKS, self-managed Kubernetes, Nomad.
