#!/usr/bin/env python3

import sys
import base64
import argparse
import requests
import logging
import re
from multiprocessing.pool import ThreadPool

logging.basicConfig()
lg = logging.getLogger(__name__)

headers = {
    'Accept': 'application/vnd.docker.distribution.manifest.v2+json',
}

def parse_args(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--login', help="Login and password for access to docker registry", required=False)
    parser.add_argument('-v', '--verbose', help="Enable verbose logging", action="store_true", required=False)
    parser.add_argument('-d', '--debug', help="Enable debug logging", action="store_true", required=False)
    parser.add_argument('-q', '--quiet', help="No output, only errors", action="store_true", required=False)
    parser.add_argument('image', help="Docker image name")
    return parser.parse_args(args)

def get_token(registry, repository, creds):
    if creds:
        creds = creds.split(':')
        creds = (creds[0], creds[1])

    res = requests.get("https://{}/v2/".format(registry), headers=headers)
    if res.status_code == 401:
        bearer = re.match(r'.*Bearer realm="([a-z0-9\\.\\/:\\-]*)",service="([a-z0-9\\.\\/:\\-]*)"', res.headers['WWW-Authenticate'])
        if bearer:
            lg.info("Authenticating in realm {}".format(bearer.group(1)))
            res = requests.get("{}?scope=repository:{}:pull&service={}".format(bearer.group(1), repository, bearer.group(2)), auth=creds)
            if (res.status_code == 200):
                return res.json()["access_token"]
            else:
                lg.error("Authentication failed: {}".format(res.json()))
                sys.exit(1)
        else:
            lg.info("Using basic auth")
    else:
        lg.info("Server didn't requested any authentication")

def parse_image(image):
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

    return {
        'host': registry,
        'path': path.split(':')[0].split('@')[0],
        'image': image,
        'digest': digest,
        'tag': tag,
    }

def resolve_digest(image):
    lg.debug("Resolving digest of image {} tag {}".format(image['path'], image['tag']))
    res = requests.get("https://{}/v2/{}/manifests/{}".format(image['host'], image['path'], image['tag']), headers=headers)
    if res.status_code != 200:
        lg.error("Unexpected error: {}".format(res.json()))
        return
    image['digest'] = res.headers['Docker-Content-Digest']
    return image

def resolve_tags(image):
    if not image["digest"]:
        image = resolve_digest(image)

    tags = requests.get("https://{}/v2/{}/tags/list?n=999".format(image['host'], image['path']), headers=headers).json()["tags"]
    lg.info("Resolving {} of all tags".format(len(tags)))

    matched_tags = []
    p = ThreadPool(8)
    tasks = []
    for tag in tags:
        i = image.copy()
        i['tag'] = tag
        tasks.append(p.apply_async(resolve_digest, args=(i,)))
    p.close()
    p.join()

    for task in tasks:
        d = task.get()
        if d and d.get("digest") == image["digest"]:
            lg.info("Found matching tag {}".format(d["tag"]))
            matched_tags.append(d["tag"])
    return matched_tags

def main():
    args = parse_args()
    if args.quiet:
        lg.setLevel(logging.ERROR)
    else:
        lg.setLevel(logging.INFO)

    if args.debug:
        lg.setLevel(logging.DEBUG)

    image = parse_image(args.image)
    lg.debug("Parsed image: {}".format(image))

    token = get_token(image['host'], image['path'], args.login)
    if token:
        lg.debug("Obtained token: {}".format(token))
        headers['Authorization'] = 'Bearer {}'.format(token)
    elif args.login:
        lg.debug("Using basic auth")
        headers['Authorization'] = 'Basic {}'.format(base64.b64encode(bytes(args.login, 'utf-8')))
    else:
        lg.debug("Proceeding without auth")

    tags = resolve_tags(image)
    print(tags)

if __name__ == '__main__':
    main()
