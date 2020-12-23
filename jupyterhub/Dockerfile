## Install jupyterhub
FROM jupyterhub/jupyterhub
LABEL maintainer="Codehub Project <info@fusemachines.com>"

## Update and upgrade
RUN apt-get update && apt-get install -y nano \
 apt-utils && pip install --upgrade pip

## Install other compatible requirements
COPY ./requirements.txt /srv/jupyterhub/requirements.txt
RUN pip install -r requirements.txt

## Add jupyrerhub configuration
ADD ./jupyterhub_config.py /srv/jupyterhub/jupyterhub_config.py

## Add cull_idle.py
ADD ./cull_idle.py /srv/jupyterhub/cull_idle.py