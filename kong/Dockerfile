FROM kong:3.9

USER root

COPY plugins/custom-auth /usr/local/share/lua/5.1/kong/plugins/custom-auth
COPY kong.yml /etc/kong/kong.yml

USER kong
