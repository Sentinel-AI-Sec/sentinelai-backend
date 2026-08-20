variable "legacy_worker_image" {
  default = "registry.internal.example.com/tinyapp-worker:latest"
}

resource "aws_ecs_task_definition" "legacy_worker_task" {
  family        = "legacy-worker-task"
  task_role_arn = aws_iam_role.legacy_worker_role.arn

  container_definitions = jsonencode([
    { name = "legacy-worker", image = var.legacy_worker_image }
  ])
}

resource "aws_iam_role" "legacy_worker_role" {
  name = "legacy-worker-role"
}
