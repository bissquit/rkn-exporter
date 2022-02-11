FROM python:3.9-slim

LABEL description="Prometheus exporter developed to indicate what your domains are blocked by Roskomnadzor agency to access from Russia" \
      source="https://github.com/bissquit/rkn-exporter"

# nobody user in base image
ARG UID=65534

COPY --chown=$UID:$UID rkn_exporter.py \
                       requirements.txt \
                       /app/

WORKDIR /app

RUN pip3 install --upgrade pip && \
    pip3 install --no-cache-dir --upgrade -r requirements.txt

EXPOSE 8080

USER $UID

CMD ["python3", "rkn_exporter.py"]
