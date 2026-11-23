FROM python:3.13-alpine
WORKDIR /app
COPY exporter.py /app/exporter.py
RUN addgroup -S exporter && adduser -S -G exporter exporter
USER exporter
EXPOSE 9108
CMD ["python", "-u", "/app/exporter.py"]
