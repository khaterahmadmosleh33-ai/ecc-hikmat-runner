FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.py /app/server.py
COPY test_runner.py /app/test_runner.py
RUN chmod 755 /app && chmod 644 /app/server.py
RUN python3 -m unittest discover -s /app -p 'test_*.py' -v && rm /app/test_runner.py
ENV PORT=10000 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 10000
CMD ["python3", "/app/server.py"]
