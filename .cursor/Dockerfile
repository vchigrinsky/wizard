# Cursor Cloud Agent base image for wizard (Jekyll + SSH clients + mdpdf).
# Do not COPY the project — Cursor checks out the commit itself.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    fonts-dejavu-core \
    fonts-liberation \
    fonts-noto-core \
    git \
    gnupg \
    libasound2t64 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libx11-6 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    openssh-client \
    ruby \
    ruby-dev \
    sudo \
    xdg-utils \
    zlib1g-dev \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Match the previously used Cloud snapshot stack (github-pages 232 / Jekyll 3.10.x).
RUN gem install --no-document github-pages -v 232

# ubuntu:24.04 already ships a non-root `ubuntu` user — only ensure passwordless sudo.
RUN echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# mdpdf + bundled Chrome for PDF builds (run as ubuntu so cache lives in $HOME).
USER ubuntu
WORKDIR /home/ubuntu
ENV PUPPETEER_CACHE_DIR=/home/ubuntu/.cache/puppeteer
RUN sudo npm install -g mdpdf \
    && cd /usr/lib/node_modules/mdpdf \
    && npx puppeteer browsers install chrome
