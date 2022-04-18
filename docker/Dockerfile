FROM python:3.7-slim


RUN apt-get update -y \
    && apt-get install -y libc-dev libpq-dev build-essential

RUN mkdir /app
COPY requirements.txt /workspace
ADD . /app
WORKDIR /app
RUN pip install -r /app/requirements.txt


ENTRYPOINT [ "python" ]

CMD [ "server.py" ]


