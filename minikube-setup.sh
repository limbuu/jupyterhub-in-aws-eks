#!/bin/bash
echo "---------------------------\nStarting the rubicon-jupyterhub dev cluster set up\n---------------------------"

## Turn on errorexit, interactive
set -ei

kubectl create configmap application-config --from-env-file=env-local.yaml
kubectl apply -f ./minikube/storage-mainfest.yaml
kubectl apply -f ./minikube/nfs-mainfest.yaml
kubectl apply -f ./minikube/mysql-mainfest.yaml
kubectl apply -f ./eks-deploy/jupyterhub-mainfest.yaml


echo "---------------------------\nCluster set up completed\n---------------------------"
