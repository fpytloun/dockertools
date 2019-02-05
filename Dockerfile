FROM python:3-alpine

WORKDIR /opt/dockertools
ADD requirements.txt /opt/dockertools
RUN pip install -r /opt/dockertools/requirements.txt

COPY dockertools /opt/dockertools/dockertools/
COPY get_image_tags.py cleanup_registry.py /opt/dockertools/
