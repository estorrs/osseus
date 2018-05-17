FROM python:3.6-jessie

COPY ./requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt

COPY . /app
WORKDIR /app

EXPOSE 8080

CMD gunicorn -c gunicorn_config.py --certfile=ssl/server.crt --keyfile=ssl/server.key --bind 0.0.0.0:8080 app:app
