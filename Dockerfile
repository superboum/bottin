FROM arm32v7/debian:stretch

RUN apt-get update && \
    apt-get -qq -y full-upgrade && \
    apt-get install -y curl gnupg2 && \
    curl -sL https://deb.nodesource.com/setup_10.x | bash - && \
    apt-get install -y nodejs build-essential && \
    mkdir -p /srv/bottin

COPY . /srv/bottin

RUN cd /srv/bottin && \
    npm install

WORKDIR /srv/bottin

ENTRYPOINT ["/usr/bin/node", "--experimental-modules", "index.mjs"]
