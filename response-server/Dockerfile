FROM python:3.11-slim

LABEL maintainer="leesean2"
LABEL project="compliance-platform-runtime-detection"

WORKDIR /app

# No external dependencies needed — stdlib only
COPY server.py .
COPY models/ ./models/
COPY core/ ./core/
COPY k8s/ ./k8s/
COPY handlers/ ./handlers/

# Non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

EXPOSE 5000

ENTRYPOINT ["python", "-u", "server.py"]
