FROM python:3.8.1
ENV PYTHONUNBUFFERED=1

RUN apt-get update --yes --quiet && apt-get install --yes --quiet --no-install-recommends \
        python-psycopg2 \
    vim \
 && rm -rf /var/lib/apt/lists/*

# Setup workdir
RUN mkdir /src
WORKDIR /src

# Python dependencies
COPY requirements.txt /src/
RUN pip install --upgrade pip
RUN pip install -r /src/requirements.txt

COPY . /src
