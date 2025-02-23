provider "aws" {
  region = var.aws_region
}

# Create VPC using AWS module
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.18.1"

  name            = "jenkins-vpc"
  cidr            = var.vpc_cidr
  azs             = [var.az]
  private_subnets = [var.private_subnets]
  public_subnets  = [var.subnet_cidr]

  enable_nat_gateway = false
  enable_vpn_gateway = false
}

# IAM Role for EKS
resource "aws_iam_role" "eks_role" {
  name = "eks-cluster-role"

  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "eks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }
  EOF
}

# IAM Policy for Jenkins to access AWS
resource "aws_iam_policy" "jenkins_policy" {
  name        = "jenkins-aws-access_admin"
  description = "Policy allowing Jenkins to manage AWS resources"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# IAM Role for Jenkins
resource "aws_iam_role" "jenkins_role" {
  name = "jenkins-eks-role"

  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }
  EOF
}

# Attach IAM Policy to Jenkins Role
resource "aws_iam_policy_attachment" "jenkins_policy_attach" {
  name       = "jenkins-policy-attach"
  roles      = [aws_iam_role.jenkins_role.name]
  policy_arn = aws_iam_policy.jenkins_policy.arn
}

# IAM Instance Profile for Jenkins Role
resource "aws_iam_instance_profile" "jenkins_instance_profile" {
  name = "jenkins-instance-profile"
  role = aws_iam_role.jenkins_role.name
}

# Security Group for Jenkins EC2
resource "aws_security_group" "jenkins_sg" {
  name   = var.jenkins_sg_name
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # ingress {
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"] # Allow access to AWS APIs
  # }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 Instance for Jenkins
resource "aws_instance" "jenkins_ec2" {
  ami                         = "ami-04b4f1a9cf54c11d0"
  instance_type               = var.instance_type
  key_name                    = var.key_name
  subnet_id                   = module.vpc.public_subnets[0]
  vpc_security_group_ids      = [aws_security_group.jenkins_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.jenkins_instance_profile.name
  associate_public_ip_address = true
  tags = {
    Name = "jenkins-ec2"
  }

  user_data = <<-EOF
  #!/bin/bash
  set -ex

  # Log output to /var/log/user_data.log
  exec > >(tee /var/log/user_data.log|logger -t user-data -s 2>/dev/console) 2>&1

  # Update and install dependencies
  sudo apt-get update -y && \
  sudo apt-get install -y snapd software-properties-common && \
  
  # Install OpenJDK 21
  sudo apt-get install -y openjdk-21-jdk && \
  
  # Install AWS CLI using snap
  sudo snap install aws-cli --classic && \

  # Install kubectl using snap
  sudo snap install kubectl --classic && \

  # Install Helm
  curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash && \

  # Add the Jenkins repository key
  sudo curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | tee /usr/share/keyrings/jenkins-keyring.asc > /dev/null && \
  
  # Add the Jenkins repository
  sudo echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/" | tee /etc/apt/sources.list.d/jenkins.list > /dev/null && \

  sudo apt-get update -y && \
  sudo apt-get install -y jenkins && \

  # Enable and start Jenkins
  sudo systemctl enable jenkins && \
  sudo systemctl start jenkins && \
  
  # Install eksctl using curl
  sudo curl -sSLO "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_Linux_amd64.tar.gz" && \
  sudo tar -xzf eksctl_Linux_amd64.tar.gz && \
  sudo mv eksctl /usr/local/bin/ && \
  sudo rm eksctl_Linux_amd64.tar.gz

  EOF
}

# resource "null_resource" "jenkins_initial_password" {
#   provisioner "local-exec" {
#     command = <<EOT
#     echo "#!/bin/bash
#     retries=12
#     while [ ! -f /var/lib/jenkins/secrets/initialAdminPassword ]; do
#       echo 'Waiting for initialAdminPassword file...'
#       retries=$((retries - 1))
#       if [ $retries -le 0 ]; then
#         echo 'InitialAdminPassword file not found after several attempts.'
#         exit 1
#       fi
#       sleep 10
#     done
#     sudo cat /var/lib/jenkins/secrets/initialAdminPassword > ./jenkins_initial_password.txt
#     echo 'InitialAdminPassword file found and saved to jenkins_initial_password.txt'
#     " > get_initial_password.sh
#     chmod +x get_initial_password.sh
#     ./get_initial_password.sh
#     EOT
#   }
# }

# resource "aws_security_group_rule" "eks_allow_jenkins" {
#   type                     = "ingress"
#   from_port                = 443
#   to_port                  = 443
#   protocol                 = "tcp"
#   security_group_id        = module.eks.cluster_security_group_id
#   source_security_group_id = aws_security_group.jenkins_sg.id
#   description              = "Allow Jenkins EC2 instance to access EKS API server"
# }





