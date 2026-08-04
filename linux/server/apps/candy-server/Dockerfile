FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin candy \
    && mkdir -p /etc/candy /opt/candy/cores \
    && chown candy:candy /etc/candy /opt/candy/cores
COPY --chmod=0755 linux/server/apps/candy-server/serverd-linux /usr/local/bin/serverd-linux
ENV CANDY_CORE_CURRENT_LINK=/opt/candy/cores/current
VOLUME ["/etc/candy", "/opt/candy/cores"]
USER candy
EXPOSE 8443/udp
ENTRYPOINT ["/usr/local/bin/serverd-linux"]
CMD ["--config", "/etc/candy/server.toml"]
