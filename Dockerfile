FROM python:3.12-alpine
# tzdata: payment dates are taken in US Central (server.py biz_date)
RUN apk add --no-cache tzdata
WORKDIR /app
COPY index.html server.py ./
CMD ["python3", "server.py"]
