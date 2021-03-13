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

## AWS Cognito Configuration
class Custom_Cognito_Authenticator(GenericOAuthenticator):
    @staticmethod
    def id_token_decoder(id_token):
        token = id_token
        region = os.environ['AWS_COGNITO_REGION']
        userpool_id = os.environ['AWS_COGNITO_USERPOOL_ID']
        app_client_id = os.environ['AWS_COGNITO_CLIENT_ID']
        keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
        # instead of re-downloading the public keys every time
        # we download them only on cold start
        # https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
        with urllib.request.urlopen(keys_url) as f:
            response = f.read()
        keys = json.loads(response.decode('utf-8'))['keys']
        # get the kid from the headers prior to verification
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']
        # search for the kid in the downloaded public keys
        key_index = -1
        for i in range(len(keys)):
            if kid == keys[i]['kid']:
                key_index = i
                break
        if key_index == -1:
            print('Public key not found in jwks.json')
            return False
        # construct the public key
        public_key = jwk.construct(keys[key_index])
        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(token).rsplit('.', 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        # verify the signature
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            print('Signature verification failed')
            return False
        print('Signature successfully verified')
        # since we passed the verification, we can now safely
        # use the unverified claims
        claims = jwt.get_unverified_claims(token)
        # additionally we can verify the token expiration
        if time.time() > claims['exp']:
            print('Token is expired')
            return False
        # and the Audience  (use claims['client_id'] if verifying an access token)
        if claims['aud'] != app_client_id:
            print('Token was not issued for this audience')
            return False
        # now we can use the claims
        print("****************************************************")
        print(claims)
        global list_of_roles
        list_of_roles = []
        if 'cognito:groups' in claims:
            list_of_roles.append(claims['cognito:groups'])
        return claims

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }
        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          body=urllib.parse.urlencode(params)  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.info("######################################")
        self.log.info(resp_json)

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        token_type = resp_json['token_type']
        id_token = resp_json['id_token']
        ########
        self.id_token_decoder(id_token)                                                                                                                  
        ########
        scope = resp_json.get('scope', '')
        if (isinstance(scope, str)):
                scope = scope.split(' ')        

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
            self.log.info("%%%%%%%%%%%%%%%%%%%%%%%%")
            self.log.info(url)
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          validate_cert=self.tls_verify,
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.info(resp_json)

        if not resp_json.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s", self.username_key, resp_json)
            return
        self.log.info(resp_json)
       
        return {
            'name': resp_json.get(self.username_key),
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': resp_json,
                'scope': scope,
            }
        }
    
c.JupyterHub.authenticator_class = Custom_Cognito_Authenticator
c.OAuthenticator.client_id = os.environ['AWS_COGNITO_CLIENT_ID']
c.OAuthenticator.client_secret = os.environ['AWS_COGNITO_CLIENT_SECRET'] 
c.OAuthenticator.login_service = os.environ['AWS_COGNITO_LOGIN_SERVICE'] 
c.OAuthenticator.oauth_callback_url = os.environ['AWS_COGNITO_OAUTH_CALLBACK_URL']

c.Authenticator.allowed_users = {'iammanshi116@gmail.com', 'abcd@gmail.com'}
c.Authenticator.admin_users = {'iammanshi116@gmail.com'}

## Custom Kubespawner
class Custon_KubeSpawner(KubeSpawner):
    @gen.coroutine
    def _start(self):
        """Start the user's pod"""

        # load user options (including profile)
        yield self.load_user_options()

        ## load roles
        self.log.info("******************************")
        self.log.info(list_of_roles)
        roles = []
        if len(list_of_roles)> 0 :
            roles = list_of_roles[0]
        else:
            roles = ['RECENTLY_SIGNED']
        self.log.info(roles)
        # custom volume mount path 
        admin_volume_path = [{'mountPath': '/home/myuser/work/',
                'name': 'persistent-storage',
                'subPath': 'home-folder'}]
        student_engine_volume_path = [{'mountPath': '/home/myuser/work/',
                'name': 'persistent-storage',
                'subPath': 'home-folder/pyspark-engine'}]
        recommendation_engine_volume_path = [{'mountPath': '/home/myuser/work/',
                'name': 'persistent-storage',
                'subPath': 'home-folder/scipy-engine'}]
        analytics_engine_volume_path = [{'mountPath': '/home/myuser/work/',
                'name': 'persistent-storage',
                'subPath': 'home-folder/datascience-engine'}]

        if ("ADMIN" in roles):
            self.image = 'aws_account_id.dkr.ecr.region.amazonaws.com/datascience-notebook:latest'
            self.volume_mounts = admin_volume_path
        elif ("PYSPARK_RUNTIME_USER" in roles):
            self.image = 'aws_account_id.dkr.ecr.region.amazonaws.com/pyspark-notebook:latest'
            self.volume_mounts = student_engine_volume_path
        elif ("SCIPY_RUNTIME_USER" in roles):
            self.image = 'aws_account_id.dkr.ecr.region.amazonaws.com/scipy-notebook:latest'
            self.volume_mounts = student_engine_volume_path
        elif ("DATASCIENCE_RUNTIME_USER" in roles):
            self.image = 'aws_account_id.dkr.ecr.region.amazonaws.com/scipy-notebook:latest'
            self.volume_mounts = student_engine_volume_path
        else:
            # spawn a normal notebook only
            self.image = 'jupyter/base-notebook:latest'

        # record latest event so we don't include old
        # events from previous pods in self.events
        # track by order and name instead of uid
        # so we get events like deletion of a previously stale
        # pod if it's part of this spawn process
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
                        "%s [%s] %s" % (event.last_timestamp or event.event_time, event.type, event.message)
                        for event in self.events
                    ]
                ),
            )
        return (pod.status.pod_ip, self.port)

c.JupyterHub.spawner_class = Custon_KubeSpawner

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




