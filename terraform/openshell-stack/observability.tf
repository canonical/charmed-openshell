# -------------- # Observability -------------- #

# The cos-lite edition of the Canonical Observability Stack, composed as
# published. The gateway has no tracing relation, and the identity platform
# needs only metrics, logging and dashboards, all of which cos-lite serves;
# the full COS edition adds capacity nothing in this stack can consume.

module "cos_lite" {
  source = "git::https://github.com/canonical/observability-stack//terraform/cos-lite?ref=${var.observability.ref}"

  model = var.models.cos_lite
  risk  = var.observability.risk

  alertmanager = var.observability.alertmanager
  catalogue    = var.observability.catalogue
  grafana      = var.observability.grafana
  loki         = var.observability.loki
  prometheus   = var.observability.prometheus
  ssc          = var.observability.ssc
  traefik      = var.observability.traefik
}
