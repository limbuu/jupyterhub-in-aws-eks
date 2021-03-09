#!/bin/bash
echo "---------------------------\nStarting the jupyterhub cluster set up in EKS\n---------------------------"

## Turn on errorexit, interactive
set -ei

kubectl create configmap application-config --from-env-file=env-dev.yaml
kubectl apply -f ./eks-deploy/storage-mainfest.yaml
kubectl apply -f ./eks-efs
kubectl apply -f ./eks-deploy/mysql-mainfest.yaml
kubectl apply -f ./eks-deploy/jupyterhub-mainfest.yaml

echo "---------------------------\nCluster set up completed in EKS\n---------------------------"
