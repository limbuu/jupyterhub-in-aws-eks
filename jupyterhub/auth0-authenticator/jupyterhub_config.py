# Configuration file for jupyterhub.
import os
import socket
from kubespawner import KubeSpawner
import dummyauthenticator
import pymysql
from oauthenticator.generic import GenericOAuthenticator, GenericLoginHandler
from tornado import gen, web
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httputil import url_concat
from traitlets.config import get_config, json, sys
from kubernetes.client.rest import ApiException
from jupyterhub.utils import exponential_backoff
import base64
import urllib
import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode
import os

#Custom Authenticator
class CustomAuth0LoginHandler(Auth0LoginHandler):
    AUTH0_SUBDOMAIN = os.environ['AUTH0_SUBDOMAIN']
    _OAUTH_AUTHORIZE_URL = "https://%s/authorize" % AUTH0_SUBDOMAIN
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/oauth/token" % AUTH0_SUBDOMAIN

class CustomAuthenticator(Auth0OAuthenticator):
    login_handler = CustomAuth0LoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        AUTH0_SUBDOMAIN = os.environ['AUTH0_SUBDOMAIN']
        code = handler.get_argument("code")
        http_client = AsyncHTTPClient()
        params = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.get_callback_url(handler)
        }
        url = "https://%s/oauth/token" % AUTH0_SUBDOMAIN

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Content-Type": "application/json"},
                          body=json.dumps(params)
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)
                   }

        req = HTTPRequest("https://%s/userinfo" % AUTH0_SUBDOMAIN,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return {
            'name': resp_json["email"],
            'auth_state': {
                'access_token': access_token,
                'auth0_user': resp_json,
            }
        }

class CustomSpawner(KubeSpawner):
    @gen.coroutine
    def _start(self):
        """Start the user's pod"""
       # Get auth0 API Explorer token of accounts-fuse-ai
        url = "https://%s/oauth/token" % os.environ['AUTH0_SUBDOMAIN']
        data = {
            'grant_type': 'client_credentials',
            'client_id': os.environ['AUTH0_API_EXPLORER_CLIENT_ID'],
            'client_secret': os.environ['AUTH0_API_EXPLORER_CLIENT_SECRET'],
            'audience': os.environ['AUTH0_API_EXPLORER_AUDIENCE'],
        }

        r = requests.post(url, data)
        access_token = json.loads(r.text)[u'access_token']

        # Get user data from auth0
        url = "https://%s/api/v2/users-by-email?email=" % os.environ['AUTH0_SUBDOMAIN'] + self.user.name
        r = requests.get(url, headers={"Authorization": "bearer " + access_token})
        user = json.loads(r.text)[0]

        # custom volume mount path 
        admin_volume_path = [{'mountPath': '/home/jovyan/work/',
                'name': 'persistent-storage',
                'subPath': 'home-folder'}]
        student_engine_volume_path = [{'mountPath': '/home/jovyan/work/',
                'name': 'persistent-storage',
                'subPath': 'home-folder/pyspark-engine'}]
        recommendation_engine_volume_path = [{'mountPath': '/home/jovyan/work/',
                'name': 'persistent-storage',
                'subPath': 'home-folder/scipy-engine'}]

        # Assign image according to user's role
        if ("ADMIN" in user[u'app_metadata'][u'authorities']):
            self.image = 'jupyter/base-notebook:latest'
            self.volume_mounts = admin_volume_path
        elif ("PYSPARK_RUNTIME_USER" in user[u'app_metadata'][u'authorities']):
            self.image = 'jupyter/pyspark-notebook:latest'
            self.volume_mounts = student_engine_volume_path
        elif ("SCIPY_RUNTIME_USER" in user[u'app_metadata'][u'authorities']):
            self.image = 'jupyter/scipy-notebook:latest'
            self.volume_mounts = student_engine_volume_path
        else:
            # spawn a normal notebook only
            self.image = 'jupyter/base-notebook:latest'

        events = self.events
        if events:
            self._last_event = events[-1].metadata.uid

        if self.storage_pvc_ensure:
            # Try and create the pvc. If it succeeds we are good. If
            # returns a 409 indicating it already exists we are good. If
            # it returns a 403, indicating potential quota issue we need
            # to see if pvc already exists before we decide to raise the
            # error for quota being exceeded. This is because quota is
            # checked before determining if the PVC needed to be
            # created.

            pvc = self.get_pvc_manifest()

            try:
                yield self.asynchronize(
                    self.api.create_namespaced_persistent_volume_claim,
                    namespace=self.namespace,
                    body=pvc
                )
            except ApiException as e:
                if e.status == 409:
                    self.log.info("PVC " + self.pvc_name + " already exists, so did not create new pvc.")

                elif e.status == 403:
                    t, v, tb = sys.exc_info()

                    try:
                        yield self.asynchronize(
                            self.api.read_namespaced_persistent_volume_claim,
                            name=self.pvc_name,
                            namespace=self.namespace)

                    except ApiException as e:
                        raise v.with_traceback(tb)

                    self.log.info("PVC " + self.pvc_name + " already exists, possibly have reached quota though.")

                else:
                    raise

        # If we run into a 409 Conflict error, it means a pod with the
        # same name already exists. We stop it, wait for it to stop, and
        # try again. We try 4 times, and if it still fails we give up.
        # FIXME: Have better / cleaner retry logic!
        retry_times = 4
        pod = yield self.get_pod_manifest()
        if self.modify_pod_hook:
            pod = yield gen.maybe_future(self.modify_pod_hook(self, pod))
        for i in range(retry_times):
            try:
                yield self.asynchronize(
                    self.api.create_namespaced_pod,
                    self.namespace,
                    pod,
                )
                break
            except ApiException as e:
                if e.status != 409:
                    # We only want to handle 409 conflict errors
                    self.log.exception("Failed for %s", pod.to_str())
                    raise
                self.log.info('Found existing pod %s, attempting to kill', self.pod_name)
                # TODO: this should show up in events
                yield self.stop(True)

                self.log.info('Killed pod %s, will try starting singleuser pod again', self.pod_name)
        else:
            raise Exception(
                'Can not create user pod %s already exists & could not be deleted' % self.pod_name)

        # we need a timeout here even though start itself has a timeout
        # in order for this coroutine to finish at some point.
        # using the same start_timeout here
        # essentially ensures that this timeout should never propagate up
        # because the handler will have stopped waiting after
        # start_timeout, starting from a slightly earlier point.
        try:
            yield exponential_backoff(
                lambda: self.is_pod_running(self.pod_reflector.pods.get(self.pod_name, None)),
                'pod/%s did not start in %s seconds!' % (self.pod_name, self.start_timeout),
                timeout=self.start_timeout,
            )
        except TimeoutError:
            if self.pod_name not in self.pod_reflector.pods:
                # if pod never showed up at all,
                # restart the pod reflector which may have become disconnected.
                self.log.error(
                    "Pod %s never showed up in reflector, restarting pod reflector",
                    self.pod_name,
                )
                self._start_watching_pods(replace=True)
            raise

        pod = self.pod_reflector.pods[self.pod_name]
        self.pod_id = pod.metadata.uid
        if self.event_reflector:
            self.log.debug(
                'pod %s events before launch: %s',
                self.pod_name,
                "\n".join(
                    [
                        "%s [%s] %s" % (event.last_timestamp, event.type, event.message)
                        for event in self.events
                        ]
                ),
            )
        return (pod.status.pod_ip, self.port)

c.Authenticator.allowed_users = {'iammanshi116@gmail.com', 'abcd@gmail.com'}
c.Authenticator.admin_users = {'iammanshi116@gmail.com'}

c.JupyterHub.spawner_class = CustomSpawner
c.JupyterHub.authenticator_class = CustomAuthenticator
c.Auth0OAuthenticator.scope = ['openid','email']
c.Authenticator.auto_login = True
c.Authenticator.whitelist = whitelist = set()
c.JupyterHub.ip = '0.0.0.0'
c.JupyterHub.hub_ip = '0.0.0.0'
c.Spawner.http_timeout = 60 * 5
c.KubeSpawner.start_timeout = 60 * 5
c.JupyterHub.cleanup_servers = False
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
host_ip = s.getsockname()[0]
s.close()
c.KubeSpawner.hub_connect_ip = host_ip
c.JupyterHub.redirect_to_server = True
c.JupyterHub.allow_named_servers = True
c.JupyterHub.cleanup_servers = True
c.JupyterHub.shutdown_on_logout = True

c.KubeSpawner.service_account = 'default'
c.KubeSpawner.image_pull_policy = 'IfNotPresent'

## database
c.JupyterHub.db_url = os.environ['DB_URL']

## switch from notebook to lab
#c.KubeSpawner.default_url ='/user/{username}/lab?'
#c.Spawner.default_url = '/lab'

# resources configuration
c.KubeSpawner.cpu_limit = 1
c.KubeSpawner.cpu_guarantee = 0.1
c.KubeSpawner.mem_limit = '1G'
c.KubeSpawner.mem_guarantee = '100M'

if os.environ['ENVIRONMENT']=='local':
    ## volumes and volume mounts in NFS (Local)
    c.KubeSpawner.volumes = [
        {
            'name': 'persistent-storage',
            'persistentVolumeClaim': {
                'claimName': 'nfs-pvc-claim'
            }
        }
    ]
else:
    ## volumes and volume mounts in EFS (AWS)
    c.KubeSpawner.volumes = [
        {
            'name': 'persistent-storage',
            'persistentVolumeClaim': {
                'claimName': 'efs-claim'
            }
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




