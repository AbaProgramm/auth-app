FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
RUN useradd -u 10001 -r app
USER 10001
EXPOSE 8080
# --timeout-graceful-shutdown < terminationGracePeriodSeconds в Deployment
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--timeout-graceful-shutdown","20"]
