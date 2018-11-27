FROM python:3-alpine

ADD requirements.txt /
RUN pip install -r /requirements.txt

ADD get_image_tags.py /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/get_image_tags.py"]
