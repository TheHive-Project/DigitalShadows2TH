FROM python:3.7-alpine

ARG pip_args=
ARG proxy=
ENV http_proxy=$proxy
ENV https_proxy=$proxy

CMD mkidr /app/log
CMD mkdir  /app/config

COPY DigitalShadows/ /app/DigitalShadows
COPY ds2markdown.py /app
COPY ds2th.py /app
COPY requirements.txt /app

WORKDIR /app
RUN apk add libmagic
RUN pip $pip_args install -r requirements.txt

ENTRYPOINT ["/app/ds2th.py"]
CMD ["--help"]

