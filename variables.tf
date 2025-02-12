variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type for Jenkins"
  default     = "t2.micro"
}

variable "key_name" {
  description = "SSH key pair name for EC2"
  default     = "key2"
}

variable "jenkins_sg_name" {
  description = "Name of the security group for Jenkins EC2"
  default     = "jenkins-sg"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the subnet"
  default     = "10.0.1.0/24"
}

variable "private_subnets" {
  default = "10.0.101.0/24"
}

variable "az" {
  description = "Availability Zone for the subnet"
  default     = "us-east-1a"
}
