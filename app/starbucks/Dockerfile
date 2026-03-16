# INTENTIONALLY INSECURE DOCKERFILE
# This Dockerfile contains deliberate security
# misconfigurations for scanner detection.

FROM python:3.9

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# VULNERABILITY: Running as root (no USER directive)
# VULNERABILITY: Exposing all ports
EXPOSE 8080

# VULNERABILITY: Debug mode enabled
ENV FLASK_DEBUG=1
ENV SECRET_KEY=hardcoded-in-dockerfile

CMD ["python", "app.py"]
