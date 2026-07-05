FROM python:3-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ssh-honeypot

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN addgroup --system --gid 999 honeypot && \
    adduser --system --uid 999 --ingroup honeypot --no-create-home honeypot && \
    mkdir -p /var/empty && \
    chown -R honeypot:honeypot /opt/ssh-honeypot

EXPOSE 2222

USER honeypot

ENTRYPOINT ["python", "ssh_honeypot.py"]
CMD ["--port", "2222"]
