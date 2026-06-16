FROM python:3.12-alpine
WORKDIR /app
COPY index.html server.py ./
CMD ["python3", "server.py"]
