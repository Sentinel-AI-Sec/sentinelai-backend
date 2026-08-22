# The deliberate distractor: a task whose image reference resolves to no Dockerfile here, so any
# chain through it is Unresolved -- "potential chain, unverified join", never a confirmed result.
#
# Copied verbatim from three files in sentinelai-fixtures, because the blocks that make this one
# join live apart there:
#
#   variable "legacy_worker_image"                    <- infra/variables.tf
#   resource "aws_ecs_task_definition" "legacy_worker_task"  <- infra/main.tf
#   resource "aws_iam_role" "legacy_worker_role"      <- infra/iam.tf
#
# Verbatim matters. An earlier version of this file was a condensed rewrite of the same blocks --
# same meaning, shorter -- and FixtureParityTests could not tell that apart from the fixture having
# actually changed underneath it. A copy that is not a copy cannot be checked against its original.

variable "legacy_worker_image" {
  description = "Image reference for the legacy worker task (ambiguous join, intentionally)"
  type        = string
  default     = "registry.internal.example.com/tinyapp-worker:latest"
}

resource "aws_ecs_task_definition" "legacy_worker_task" {
  family                   = "legacy-worker-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.legacy_worker_role.arn
  task_role_arn            = aws_iam_role.legacy_worker_role.arn

  container_definitions = jsonencode([
    {
      name  = "legacy-worker"
      image = var.legacy_worker_image
    }
  ])
}

resource "aws_iam_role" "legacy_worker_role" {
  name = "legacy-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}
