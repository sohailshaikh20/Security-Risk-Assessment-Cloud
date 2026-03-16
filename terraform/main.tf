terraform {
  required_version = ">= 1.5.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
  }
}

provider "kubernetes" {
  config_path = "~/.kube/config"
}

# ==========================================
# Kubernetes Deployment (INTENTIONALLY RISKY)
# ==========================================
# These misconfigurations are deliberate test
# targets for the DevSecOps security scanners.
# DO NOT deploy this to any real cluster.
# ==========================================

resource "kubernetes_deployment" "vulnerable_app" {

  metadata {
    name = "devsecops-demo-app"

    labels = {
      app         = "demo"
      environment = var.environment
    }
  }

  spec {

    replicas = 2

    selector {
      match_labels = {
        app = "demo"
      }
    }

    template {

      metadata {
        labels = {
          app = "demo"
        }
      }

      spec {

        container {

          name = "demo-container"

          # VULNERABILITY 1
          # latest tag → version drift risk
          image = "nginx:latest"

          port {
            container_port = 80
          }

          # VULNERABILITY 2 + 3 (merged into single block)
          # container running as root AND privileged
          security_context {
            run_as_user = 0
            privileged  = true
          }

          # VULNERABILITY 4
          # missing resource limits (intentional)

          env {
            name  = "ENV"
            value = var.environment
          }

          # VULNERABILITY 6
          # hardcoded secret in env
          env {
            name  = "DB_PASSWORD"
            value = "hardcoded-secret-123"
          }
        }
      }
    }
  }
}

# ==========================================
# Kubernetes Service
# ==========================================

resource "kubernetes_service" "vulnerable_service" {

  metadata {
    name = "devsecops-demo-service"
  }

  spec {

    selector = {
      app = "demo"
    }

    port {
      port        = 80
      target_port = 80
    }

    # VULNERABILITY 5
    # public exposure
    type = "LoadBalancer"
  }
}
