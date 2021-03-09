# Configuration file for jupyterhub.
import os
import socket
from kubespawner import KubeSpawner
import dummyauthenticator
import pymysql

## main configuration
c.JupyterHub.spawner_class = KubeSpawner
c.JupyterHub.authenticator_class = 'dummyauthenticator.DummyAuthenticator'

c.JupyterHub.ip = '0.0.0.0'
c.JupyterHub.hub_ip = '0.0.0.0'
c.Spawner.http_timeout = 60 * 5
c.KubeSpawner.start_timeout = 60 * 5
c.Authenticator.admin_users = {"iammanshi116@gmail.com"}
c.JupyterHub.cleanup_servers = False
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
host_ip = s.getsockname()[0]
s.close()
c.KubeSpawner.hub_connect_ip = host_ip
c.JupyterHub.redirect_to_server = True
c.JupyterHub.allow_named_servers = True

c.KubeSpawner.service_account = 'default'
c.KubeSpawner.image_pull_policy = 'IfNotPresent'
#c.KubeSpawner.image = 'jupyter/pyspark-notebook:latest'

## database
c.JupyterHub.db_url = os.environ['DB_URL']
#c.JupyterHub.db_url = 'mysql+pymysql://root:root@172.20.186.77:3306/rbjhdb'
## profiles
c.KubeSpawner.profile_list = [
    {
        'display_name': 'PySpark Environment',
        'default': True,
        'kubespawner_override': {
            'image': 'jupyter/pyspark-notebook:latest',
            'cpu_limit': 1,
            'cpu_guarantee': 0.1,
            'mem_limit': '1G',
            'mem_guarantee': '100M'
        },
        'description': 'Using this runtime environment, you get access to pyspark notebook'
    }, {
        'display_name': 'Scipy Environment',
        'kubespawner_override': {
            'image': 'jupyter/scipy-notebook:latest',
            'cpu_limit': 1,
            'cpu_guarantee': 0.1,
            'mem_limit': '1G',
            'mem_guarantee': '100M'
        },
        'description': 'Using this runtime environment, you can access to scipy-notebook'
    }
]

## cull_idle
c.JupyterHub.services = [
    {
        'name': 'cull-idle',
        'admin': True,
        'command': 'python3 cull_idle.py --timeout=600'.split(),
    }
]
