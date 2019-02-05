import re
import base64
import requests
import logging
from multiprocessing.pool import ThreadPool
from datetime import datetime

logging.basicConfig()
lg = logging.getLogger(__name__)


class Registry(object):
    def __init__(self, registry):
        self.tokens = {}
        self.registry = registry
        self.headers = {
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json',
        }

    def login(self, creds):
        if type(creds) == str:
            creds = creds.split(':')
            creds = (creds[0], creds[1])

        self.creds = creds
        token = self.get_token("repository:ubuntu:pull")
        if token:
            lg.debug("Obtained token: {}".format(token))
        elif self.creds:
            lg.debug("Using basic auth")
            self.headers['Authorization'] = 'Basic {}'.format(base64.b64encode(bytes(args.login, 'utf-8')))
        else:
            lg.debug("Proceeding without auth")

    def get_images(self):
        res = self.get("https://{}/v2/_catalog/".format(self.registry), scope="registry:catalog:*")
        if res.status_code != 200:
            raise Exception("Unexpected error: status_code={}, response={}".format(res.status_code, res.text))
        images = []
        for repository in res.json()['repositories']:
            images.append(Image("{}/{}".format(self.registry, repository), self))
        return images

    def get_image(self, image):
        return Image("{}/{}".format(self.registry, image), self)

    def get_token(self, scope):
        if scope in self.tokens.keys():
            return self.tokens[scope]
        res = self.get("https://{}/v2/".format(self.registry))
        if res.status_code == 401:
            bearer = re.match(r'.*Bearer realm="([a-z0-9\\.\\/:\\-]*)",service="([a-z0-9\\.\\/:\\-]*)"', res.headers['WWW-Authenticate'])
            if bearer:
                lg.debug("Authenticating in realm {}".format(bearer.group(1)))
                get_url = "{}?scope={}&service={}".format(bearer.group(1), scope, bearer.group(2))
                res = self.get(get_url, auth=self.creds)
                if (res.status_code == 200):
                    token = res.json()
                    if token.get("token"):
                        lg.debug("Obtained token for scope {}".format(scope))
                        self.tokens[scope] = token["token"]
                        return token["token"]
                    elif token.get("access_token"):
                        lg.debug("Obtained token for scope {}".format(scope))
                        self.tokens[scope] = token["access_token"]
                        return token["access_token"]
                    else:
                        raise Exception("Unexpected response from server: {}".format(token))
                else:
                    raise Exception ("Authentication failed: status_code={}, response={}".format(res.status_code, res.text))
            else:
                lg.debug("Using basic auth")
        else:
            lg.debug("Server didn't requested any authentication")

    def image(self, image):
        return Image(image, self)

    def get(self, *args, **kwargs):
        headers = self.headers.copy()
        scope = kwargs.pop('scope', None)
        if scope and self.tokens:
            token = self.get_token(scope)
            headers['Authorization'] = 'Bearer {}'.format(token)
        res = requests.get(*args, **kwargs, headers=headers)
        return res

    def delete(self, *args, **kwargs):
        headers = self.headers.copy()
        scope = kwargs.pop('scope', None)
        if scope and self.tokens:
            token = self.get_token(scope)
            headers['Authorization'] = 'Bearer {}'.format(token)
        res = requests.delete(*args, **kwargs, headers=headers)
        return res

class Image(object):
    def __init__(self, image, registry=None):
        self.tags = []
        self.config = {}
        self.parse_image(image)
        if registry:
            self.registry = registry
        else:
            self.registry = Registry(self.host)

    def parse_image(self, image):
        digest = None
        tag = "latest"
        registry = image.split('/')[0]
        if re.match('^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}', registry):
            # Registry part is url which means that we are using unofficial registry
            path = image.replace("{}/".format(registry), '')
        else:
            registry = "index.docker.io"
            path = image

        if re.match('.*@(sha256:.*)', path):
            digest = re.match('.*(sha256:.*)', path).group(1)
            tag = None
        elif re.match('.*:(.*)$', path):
            tag = re.match('.*:(.*)$', path).group(1)

        self.host = registry
        self.path = path.split(':')[0].split('@')[0]
        self.image = image
        self.digest = digest
        self.tag = tag

    def resolve_digest(self):
        lg.debug("Resolving digest of image {}".format(self.name,))
        res = self.registry.get("https://{}/v2/{}/manifests/{}".format(self.host, self.path, self.tag), scope="repository:{}:pull".format(self.path))
        if res.status_code != 200:
            raise Exception("Unexpected error: status_code={}, response={}".format(res.status_code, res.text))
        self.digest = res.headers['Docker-Content-Digest']
        return self.digest

    def get_tags(self):
        if not self.tags:
            lg.info("Getting all tags for image {}/{}".format(self.host, self.path))
            res = self.registry.get("https://{}/v2/{}/tags/list?n=999".format(self.host, self.path), scope="repository:{}:pull".format(self.path))
            if res.status_code != 200:
                raise Exception("Unexpected error: status_code={}, response={}".format(res.status_code, res.text))
            self.tags = res.json()["tags"]
        return self.tags

    def get_image_tag(self, tag):
        """
        Return image object with different tag
        """
        image = Image(self.image, self.registry)
        image.tag = tag
        return image

    def get_image_tags(self):
        """
        Return image object for each tag
        """
        images = []
        for tag in self.get_tags():
            i = Image(self.image, self.registry)
            i.tag = tag
            images.append(i)
        return images

    @property
    def name(self):
        return self.get_name()

    def get_name(self, tag=False):
        if tag == False and self.digest:
            tag = "@{}".format(self.digest)
        elif self.tag:
            tag = ":{}".format(self.tag)
        else:
            tag = ":latest"
        return '{}/{}{}'.format(self.host, self.path, tag)

    def __repr__(self):
        return self.name()

    def delete(self):
        res = self.registry.delete("https://{}/v2/{}/manifests/{}".format(self.host, self.path, self.digest), scope="repository:{}:*".format(self.path))
        if res.status_code == 404:
            lg.info("Image {} seems to be already deleted".format(self.name))
            return
        if res.status_code != 202:
            raise Exception("Deleting image {} failed with status code {}: {}".format(self.name, res.status_code, res.text))

    def get_config(self):
        lg.debug("Getting config for image {}".format(self.name))
        res = self.registry.get("https://{}/v2/{}/manifests/{}".format(self.host, self.path, self.tag or self.digest), scope="repository:{}:pull".format(self.path))

        if res.status_code != 200:
            raise Exception("Unexpected error: status_code={}, response={}".format(res.status_code, res.text))

        self.digest = res.headers['Docker-Content-Digest']
        config_digest = res.json()["config"]["digest"]

        self.config = self.registry.get("https://{}/v2/{}/blobs/{}".format(self.host, self.path, config_digest), scope="repository:{}:pull".format(self.path)).json()
        return self.config

    @property
    def created(self):
        if not self.config:
            self.get_config()
        return datetime.strptime(self.config['created'][:-4], "%Y-%m-%dT%H:%M:%S.%f")

    def resolve_tags(self):
        """
        Try to find other tags that match our digest
        """
        if not self.digest:
            self.resolve_digest()

        tags = self.get_tags()
        lg.info("Resolving {} of all tags".format(len(tags)))

        matched_tags = []
        p = ThreadPool(8)
        tasks = []
        images = []
        for tag in tags:
            i = self.get_image_tag(tag)
            tasks.append(p.apply_async(i.resolve_digest))
            images.append(i)
        p.close()
        p.join()

        for i in images:
            if i.digest == self.digest:
                lg.info("Found matching tag {}".format(i.tag))
                matched_tags.append(i.tag)
        return matched_tags
