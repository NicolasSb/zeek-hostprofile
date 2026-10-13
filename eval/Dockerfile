# Pinned Python for the analysis, so results do not depend on the host.
FROM python:3.12.3-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
