#!/usr/bin/env python3

import argparse
import logging
from dockertools.registry import Registry, Image

logging.basicConfig()
lg = logging.getLogger(__name__)
lg_root = logging.getLogger('')

def parse_args(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--login', help="Login and password for access to docker registry", required=False)
    parser.add_argument('-v', '--verbose', help="Enable verbose logging", action="store_true", required=False)
    parser.add_argument('-d', '--debug', help="Enable debug logging", action="store_true", required=False)
    parser.add_argument('-q', '--quiet', help="No output, only errors", action="store_true", required=False)
    parser.add_argument('image', help="Docker image name")
    return parser.parse_args(args)

def main():
    args = parse_args()
    if args.quiet:
        lg_root.setLevel(logging.ERROR)
    else:
        lg_root.setLevel(logging.INFO)

    if args.debug:
        lg_root.setLevel(logging.DEBUG)

    image = Image(args.image)
    image.registry.login(args.login)
    print(image.resolve_tags())

if __name__ == '__main__':
    main()
