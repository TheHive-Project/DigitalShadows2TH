FROM python:3.7-alpine

copy . /app
WORKDIR /app
RUN apk add libmagic
RUN pip install -r requirements.txt

ENTRYPOINT ["/app/ds2th.py"]
CMD ["--help"]

