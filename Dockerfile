FROM fedora:28

RUN dnf upgrade -y && \
    dnf install -y curl && \
    curl -sL https://rpm.nodesource.com/setup_10.x | bash - && \
    dnf install -y nodejs gcc-c++ make && \
    mkdir -p /srv/bottin

COPY . /srv/bottin

RUN cd /srv/bottin && \
    npm install

WORKDIR /srv/bottin

ENTRYPOINT ["/usr/bin/node", "--experimental-modules", "index.mjs"]
