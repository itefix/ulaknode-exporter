# syntax=docker/dockerfile:1
FROM python:3.12-slim

ARG VERSION=dev
ENV EXPORTER_VERSION=${VERSION}

WORKDIR /app
COPY exporter.py /app/exporter.py

EXPOSE 9101
CMD ["python", "exporter.py"]
