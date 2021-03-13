# Jupyterhub in AWS EKS
## Minikube SetUp(Local)
### Prerequsites SetUp
* minikube: `Minikube` is a tool that creates a single node(Virtual Machine) Kubernetes cluster on your computer using VirtualBox or Docker. To install minikube follow this [link.](https://minikube.sigs.k8s.io/docs/start/)
* kubectl: `kubectl` is CLI tool that can be used to deploy applications, inspect and manage cluster resources and view logs. To installl `kubectl` follow this [link.](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)
* skaffold: `Skaffold` is a CLI tool that facilates the continuous development and deployment of kubernetes native-applications. It also handles the workflow for building, pushing and deploying applications and provide building blocks for creating CI/CD pipelines for local as well as remote Kubernetes cluster. To install `skaffold` follow this [link.](https://skaffold.dev/docs/install/)

### 1. Start Minikube 
Start minikube with different profile/cluster name as follows:
```
$ minikube start -p <jupyterhub-cluster-name>
```
### 2. Deploy Workloads
Jupyterhub needs a database to persist users, hub and notebook information and also a newtork file system for the notebooks and other files created by users to persist after the container server is shutodown. 

Therefore, for database we use `mysql` and `nfs` as local network file system. Also, we use `kubernetes configmap` as secret to add environment variables and mount it to `jupyterhub deployment`. We run a `bash script` to do all these prerequsite deployments including `jupyterhub deployment`.
```
$ chmod +x minikube-setup.sh
$ ./minikube-setup.sh
```
### 3. Access Jupyterhub
Run following command and access `jupyterhub` at `localhost:9000`.
```
$ skaffold dev --port-forward
```
`skaffold` tracks any changes you make and dynamically deploy the changes to the minikube k8s cluster deployments. 
To change `skaffold` configuration change `skaffold.yaml` file values.
## AWS EKS SetUp(Cloud)
### Prerequsites SetUp
* AWS CLI: `aws cli` is a CLI tool for working with AWS service, including Amazon EKS. To install `aws-cli` follow this [link.](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html)
* kubectl: `kubectl` is CLI that can be used to deploy applications, inspect and manage cluster resources and view logs. To installl `kubectl` follow this [link.](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)
* eksctl: `eksctl` is a simple CLI tool for create AWS-EKS cluster. To install `eksctl` follwo this [link.](https://github.com/weaveworks/eksctl#Installation)

### 1. Create EKS Cluster
There are different ways to create EKS cluster (eksctl,terraform,console,etc). Here, we will use `eksctl` to create a eks cluster to deploy our `jupyterhub workloads`.
```
$ eksctl create cluster -f ./eks-deploy/cluster.yaml
```
For more advaced configurations and commands of `eksctl`, follow this [link.](https://eksctl.io/usage/creating-and-managing-clusters/)
### 2. Acess EKS Cluster Locally 
First, update `kubeconfig` with newly created cluster.
```
$ aws eks --region <aws-region> update-kubeconfig --name <cluster-name>
```
Second, run following commands to use the newly created cluster `context-name.`
```
$ kubectl config get-contexts
$ kubectl config use-context <context-name>
```
### 3. Deploy Workloads
Jupyterhub needs a database to persist users, hub and notebook information and also a newtork file system for the notebooks and other files created by users to persist after the container server is shutodown. 

Therefore, for database we use `mysql` and `nfs` as local network file system. Also, we use `kubernetes configmap` as secret to add environment variables and mount it to `jupyterhub deployment`. We run a `bash script` to do all these prerequsite deployments including `jupyterhub deployment`.
```
$ chmod +x minikube-setup.sh
$ ./eks-setup.sh
```

### 4. Access Jupyterhub
Here, we have exposed the `jupyterhub` workload service in k8s native loadbalncer. Using that loadbalancer we can access `jupyterhub` with a dns like following :
```
$  kubectl get svc
NAME                 TYPE           CLUSTER-IP       EXTERNAL-IP                                                     PORT(S)          AGE
jupyterhub-service   LoadBalancer   172.20.207.206   aca434079a4cb0a9961170c1-23367063.us-west-2.elb.amazonaws.com   8000:32678/TCP   28h
```
Now, you can access `jupyterhub` at `<external-ip>:8000`
