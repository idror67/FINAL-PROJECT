# AWS EC2 Jenkins CD Pipeline on AWS EKS Cluster

## Project Overview
This project sets up a CI/CD pipeline in AWS using Terraform, Jenkins, and Kubernetes to deploy a Flask-based contacts application on an EKS cluster. The infrastructure is managed using Terraform and Ansible, while Jenkins orchestrates the deployment.

## Project Structure
- **STEP1: Jenkins Setup** (File: `JENKINS.TF`)
  - Provision an EC2 instance for Jenkins.
  - Set up security groups and IAM roles for access to AWS resources.
  - Configure Jenkins with necessary tools: Java, Jenkins, kubectl, eksctl, and AWS CLI.

- **STEP2: EKS Cluster Setup** (Directory: `EKS`, File: `EKS.TF`)
  - Create an EKS cluster with two managed nodes.
  - Configure networking using VPC and subnet modules.
  - Enable public and private access to the Kubernetes API.

- **STEP3: Jenkins Pipeline** (File: `JENKINSFILE`)
  - Define the CI/CD pipeline in Jenkins.
  - Pull source code from the GitHub repository.
  - Deploy the application to the EKS cluster using Kubernetes manifests.

- **STEP4: Flask Contacts App Deployment** (Directory: `FLASKCONTACTAPP`)
  - Deploy the Flask contacts application to EKS.
  - Ensure the service is accessible on port 5000.
  - Includes optional monitoring setup with Prometheus.

## Bonus: Monitoring with Prometheus
1. Install Prometheus on the EKS cluster using Helm:
   ```sh
   helm install prometheus prometheus-community/kube-prometheus-stack
   ```
2. Update the Prometheus service type to LoadBalancer:
   ```sh
   helm upgrade prometheus prometheus-community/kube-prometheus-stack --set prometheus.service.type=LoadBalancer
   ```
3. Access Prometheus via browser on port 9090.
4. Uninstall the default MySQL Exporter:
   ```sh
   helm uninstall mysql-exporter
   ```
5. Install MySQL Exporter with a custom values file:
   ```sh
   helm install mysql-exporter prometheus-community/prometheus-mysql-exporter -f mysql-exporter-values.yaml
   ```
6. Apply the Flask service monitor:
   ```sh
   kubectl apply -f flask-service-monitor.yaml
   ```

## Repository Structure
```
FINAL-PROJECT/
│── JENKINS.TF
│── EKS/
│   └── EKS.TF
│── JENKINSFILE
│── FLASKCONTACTAPP/
│   ├── Kubernetes manifests
│   ├── flask-service-monitor.yaml
│   └── mysql-exporter-values.yaml
└── .gitignore (Excludes AWS credentials)
```

## GitHub Repository
[Project Repository](https://github.com/idror67/FINAL-PROJECT.git)

