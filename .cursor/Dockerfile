# Cursor Cloud Agent base image for wizard (Jekyll + SSH clients).
# Do not COPY the project — Cursor checks out the commit itself.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    openssh-client \
    ruby \
    ruby-dev \
    sudo \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Match the previously used Cloud snapshot stack (github-pages 232 / Jekyll 3.10.x).
RUN gem install --no-document github-pages:232

RUN useradd -ms /bin/bash ubuntu \
    && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER ubuntu
WORKDIR /home/ubuntu
