FROM python:3.6-jessie

COPY ./requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt

COPY . /app
WORKDIR /app

EXPOSE 443

CMD gunicorn -c gunicorn_config.py app:app

