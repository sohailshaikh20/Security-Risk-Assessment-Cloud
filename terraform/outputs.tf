output "deployment_name" {
  description = "Name of the deployed Kubernetes deployment"
  value       = kubernetes_deployment.vulnerable_app.metadata[0].name
}

output "service_name" {
  description = "Name of the deployed Kubernetes service"
  value       = kubernetes_service.vulnerable_service.metadata[0].name
}
