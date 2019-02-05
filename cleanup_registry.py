#!/usr/bin/env python3

import sys
import argparse
import logging
import re
from multiprocessing.pool import ThreadPool
from dockertools.registry import Registry, Image
from datetime import timedelta, datetime

logging.basicConfig()
lg = logging.getLogger('')

def parse_args(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--login', help="Login and password for access to docker registry", required=False)
    parser.add_argument('-i', '--images', nargs='+', help="Run cleanup for selected images", required=False)
    parser.add_argument('-j', '--jobs', type=int, default=8, help="Number of jobs for repository operations", required=False)
    parser.add_argument('--keep-tags', help="Regular expression of tags to keep", required=False)
    parser.add_argument('--keep-age', type=int, help="Keep images younger than this number of hours", required=False)
    parser.add_argument('--keep-file', help="File with definition of images to keep", required=False)
    parser.add_argument('-v', '--verbose', help="Enable verbose logging", action="store_true", required=False)
    parser.add_argument('-d', '--debug', help="Enable debug logging", action="store_true", required=False)
    parser.add_argument('--dry', help="Dry-run only", action="store_true", required=False)
    parser.add_argument('-q', '--quiet', help="No output, only errors", action="store_true", required=False)
    parser.add_argument('registry', help="Docker registry")
    return parser.parse_args(args)

def main():
    args = parse_args()
    if args.quiet:
        lg.setLevel(logging.ERROR)
    else:
        lg.setLevel(logging.INFO)

    if args.debug:
        lg.setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.INFO)

    tags_regex = re.compile('^$')
    if args.keep_tags:
        tags_regex = re.compile(args.keep_tags)

    registry = Registry(args.registry)
    registry.login(args.login)

    whitelist_images = []
    if args.keep_file:
        lg.info("Processing file {} with list of whitelisted images".format(args.keep_file))
        with open(args.keep_file, 'r') as fh:
            for entry in fh.readlines():
                whitelist_images.append(registry.get_image(entry))

    images = []
    if args.images:
        for i in args.images:
            images.append(registry.get_image(i))
    else:
        images = registry.get_images()

    for image in images:
        lg.info("Processing image {}/{}".format(image.host, image.path))
        image_tags = []
        p = ThreadPool(args.jobs)
        for tag in image.get_image_tags():
            p.apply_async(tag.get_config)
            image_tags.append(tag)
        p.close()
        p.join()

        delete_images = {}
        keep_images = []

        # First iteration for basic sorting of keep vs. delete
        for tag in image_tags:
            if re.match(tags_regex, tag.tag):
                lg.info("Not deleting image {} as it's matching whitelisted tags".format(tag.get_name(tag=True)))
                keep_images.append(tag)
                continue

            if whitelist_images:
                for wi in whitelist_images:
                    # Whitelisted image has digest and it matches
                    if wi.digest and tag.digest == wi.digest:
                        lg.info("Not deleting image {} as it's digest is matching whitelisted digests".format(tag.get_name(tag=True)))
                        keep_images.append(tag)
                        break

                    # Whitelisted image doesn't have digest but tag matches
                    if not wi.digest and wi.tag == tag.tag:
                        lg.info("Not deleting image {} as it's matching whitelisted tags".format(tag.get_name(tag=True)))
                        keep_images.append(tag)
                        break
                if tag in keep_images:
                    continue

            if args.keep_age:
                if tag.created > datetime.now() - timedelta(hours=args.keep_age):
                    lg.info("Not deleting image {} as it's younger than {} hours".format(tag.get_name(tag=True), args.keep_age))
                    keep_images.append(tag)
                    continue

            # Mark rest for deletion
            if tag not in keep_images:
                try:
                    delete_images[tag.digest].append(tag)
                except KeyError:
                    delete_images[tag.digest] = [tag]


        # Second iteration to process interconnected images
        for digest, images in delete_images.copy().items():
            # Don't delete if another tag of same sha is already whitelisted
            for tag in images:
                for i in keep_images:
                    if i.digest == tag.digest:
                        lg.info("Not deleting image {} as it has same digest as already whitelisted image".format(tag.get_name(tag=True)))
                        keep_images.append(tag)
                        delete_images.pop(tag.digest)
                        break
                if tag in keep_images:
                    break

        if args.dry:
            lg.info("Deleting {} images (dry-run)".format(len(delete_images)))
        else:
            lg.info("Deleting {} images".format(len(delete_images)))

        p = ThreadPool(args.jobs)
        for images in delete_images.values():
            lg.info("Deleting image {} ({})".format(images[0].name, ", ".join([i.tag for i in images])))
            if not args.dry:
                p.apply_async(images[0].delete)
        p.close()
        p.join()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        lg.info("Interrupted")
        sys.exit(1)
