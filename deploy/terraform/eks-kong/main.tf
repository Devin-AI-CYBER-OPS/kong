# Security: Terraform module for EKS + Kong federal deployment.
# Provisions a private EKS cluster, Kong namespace with resource quotas,
# AWS Secrets Manager integration, ACM TLS certs, and STIG-aligned security groups.
# References: NIST SP 800-53 SC-7/SC-8, CIS EKS Benchmark, DISA STIG network segmentation

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "s3" {
    # Configure per-environment: bucket, key, region, dynamodb_table
  }
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "kong-federal-eks"
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.31"
}

variable "vpc_id" {
  description = "VPC ID where the EKS cluster will be deployed"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for EKS worker nodes"
  type        = list(string)
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-gov-west-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "kong_domain" {
  description = "Domain name for the Kong proxy TLS certificate"
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "kong-federal"
    ManagedBy   = "terraform"
    Compliance  = "STIG"
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = var.tags
  }
}

# ---------------------------------------------------------------------------
# EKS Cluster (private endpoint only)
# ---------------------------------------------------------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  vpc_id     = var.vpc_id
  subnet_ids = var.private_subnet_ids

  # Security: private-only API endpoint per STIG network segmentation
  cluster_endpoint_public_access  = false
  cluster_endpoint_private_access = true

  # Security: envelope encryption for K8s secrets at rest
  cluster_encryption_config = {
    provider_key_arn = aws_kms_key.eks.arn
    resources        = ["secrets"]
  }

  cluster_enabled_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]

  eks_managed_node_groups = {
    kong-security-zone = {
      name           = "kong-nodes"
      instance_types = ["m6i.xlarge"]
      min_size       = 2
      max_size       = 10
      desired_size   = 3

      labels = {
        "node-role.kubernetes.io/security-zone" = "api-gateway"
      }

      taints = [
        {
          key    = "security-zone"
          value  = "api-gateway"
          effect = "NO_SCHEDULE"
        }
      ]

      # Security: encrypted EBS volumes
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 100
            volume_type           = "gp3"
            encrypted             = true
            delete_on_termination = true
          }
        }
      }
    }
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# KMS key for EKS secrets encryption
# ---------------------------------------------------------------------------
resource "aws_kms_key" "eks" {
  description             = "KMS key for EKS secrets encryption — ${var.cluster_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.cluster_name}-eks-secrets"
  target_key_id = aws_kms_key.eks.key_id
}

# ---------------------------------------------------------------------------
# Kong namespace with resource quotas
# ---------------------------------------------------------------------------
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", var.cluster_name, "--region", var.region]
  }
}

resource "kubernetes_namespace" "kong" {
  metadata {
    name = "kong"
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }
}

resource "kubernetes_resource_quota" "kong" {
  metadata {
    name      = "kong-quota"
    namespace = kubernetes_namespace.kong.metadata[0].name
  }

  spec {
    hard = {
      "requests.cpu"    = "8"
      "requests.memory" = "16Gi"
      "limits.cpu"      = "16"
      "limits.memory"   = "32Gi"
      pods              = "50"
    }
  }
}

# ---------------------------------------------------------------------------
# AWS Secrets Manager for Kong secrets
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "kong_tls_cert" {
  name                    = "${var.cluster_name}/kong/tls-cert"
  description             = "Kong proxy TLS certificate"
  recovery_window_in_days = 30
  tags                    = var.tags
}

resource "aws_secretsmanager_secret" "kong_oidc_client_secret" {
  name                    = "${var.cluster_name}/kong/oidc-client-secret"
  description             = "Keycloak OIDC client secret for Kong"
  recovery_window_in_days = 30
  tags                    = var.tags
}

resource "aws_secretsmanager_secret" "elastic_api_key" {
  name                    = "${var.cluster_name}/kong/elastic-api-key"
  description             = "Elasticsearch API key for Kong logging"
  recovery_window_in_days = 30
  tags                    = var.tags
}

# ---------------------------------------------------------------------------
# ACM certificate for Kong proxy TLS
# ---------------------------------------------------------------------------
resource "aws_acm_certificate" "kong" {
  domain_name       = var.kong_domain
  validation_method = "DNS"
  tags              = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Security Groups — STIG network segmentation
# ---------------------------------------------------------------------------
resource "aws_security_group" "kong_proxy" {
  name_prefix = "${var.cluster_name}-kong-proxy-"
  vpc_id      = var.vpc_id
  description = "Security group for Kong proxy pods — allows HTTPS ingress only"

  ingress {
    description = "HTTPS from load balancer"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]   # Adjust to your VPC CIDR
  }

  egress {
    description = "Upstream services"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = merge(var.tags, { Name = "${var.cluster_name}-kong-proxy" })
}

resource "aws_security_group" "kong_admin" {
  name_prefix = "${var.cluster_name}-kong-admin-"
  vpc_id      = var.vpc_id
  description = "Security group for Kong admin API — internal only"

  ingress {
    description = "Admin API from within cluster"
    from_port   = 8444
    to_port     = 8444
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = merge(var.tags, { Name = "${var.cluster_name}-kong-admin" })
}

# ---------------------------------------------------------------------------
# IRSA role for Kong pods
# ---------------------------------------------------------------------------
module "kong_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name = "${var.cluster_name}-kong-irsa"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kong:kong"]
    }
  }

  role_policy_arns = {
    secrets = aws_iam_policy.kong_secrets_read.arn
  }
}

resource "aws_iam_policy" "kong_secrets_read" {
  name        = "${var.cluster_name}-kong-secrets-read"
  description = "Allow Kong pods to read secrets from AWS Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadKongSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = [
          aws_secretsmanager_secret.kong_tls_cert.arn,
          aws_secretsmanager_secret.kong_oidc_client_secret.arn,
          aws_secretsmanager_secret.elastic_api_key.arn,
        ]
      },
      {
        Sid      = "DecryptSecrets"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.eks.arn]
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "kong_namespace" {
  description = "Kong Kubernetes namespace"
  value       = kubernetes_namespace.kong.metadata[0].name
}

output "kong_irsa_role_arn" {
  description = "IRSA role ARN for Kong service account"
  value       = module.kong_irsa.iam_role_arn
}

output "acm_certificate_arn" {
  description = "ACM certificate ARN for Kong proxy TLS"
  value       = aws_acm_certificate.kong.arn
}
