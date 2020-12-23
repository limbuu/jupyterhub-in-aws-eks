#!/bin/bash
echo "---------------------------\nStarting the rubicon-jupyterhub dev cluster set up\n---------------------------"

## Turn on errorexit, interactive
set -ei

kubectl create configmap application-config --from-env-file=env.properties
kubectl apply -f ./mysql-deploy/mysql-mainfest.yaml
kubectl apply -f rubicon-jupyterhub-mainfest.yaml


echo "---------------------------\nCluster set up completed\n---------------------------"
