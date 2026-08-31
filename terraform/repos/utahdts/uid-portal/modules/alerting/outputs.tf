output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "alert_topic_name" {
  value = aws_sns_topic.alerts.name
}

output "dlq_arn" {
  value = aws_sqs_queue.dlq.arn
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}

output "dlq_name" {
  value = aws_sqs_queue.dlq.name
}
