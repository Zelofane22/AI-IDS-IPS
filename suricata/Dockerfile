FROM jasonish/suricata:8.0.8

COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/local.rules /etc/suricata/rules/local.rules
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && chmod -R a+rX /etc/suricata

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
