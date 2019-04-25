FROM python:3.7-alpine

CMD  mkidr /app/log
CMD mkdir  /app/config

COPY DigitalShadows/ /app/DigitalShadows
COPY ds2markdown.py /app
COPY ds2th.py /app
COPY requirements.txt /app

WORKDIR /app
RUN apk add libmagic
RUN pip install -r requirements.txt

ENTRYPOINT ["/app/ds2th.py"]
CMD ["--help"]

