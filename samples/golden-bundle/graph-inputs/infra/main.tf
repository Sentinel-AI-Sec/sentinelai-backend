resource "aws_ecs_task_definition" "order_task" {
  family                   = "order-task"
  execution_role_arn       = aws_iam_role.order_task_role.arn
  task_role_arn            = aws_iam_role.order_task_role.arn

  container_definitions = jsonencode([
    {
      name  = "order-service"
      image = "registry.hub.docker.com/tinyapp/order:1.4.2"
    }
  ])
}
