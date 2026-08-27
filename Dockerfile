# La interfaz web de sshCryptoChecker en un contenedor mínimo.
#
# Lo más cómodo es `make web-up` / `make web-down` (usa docker-compose.yml). A
# mano:
#
#   docker build -t sshcryptochecker-web .
#   # Abierta por defecto (sin token, sin usuarios): cualquiera que alcance el
#   # puerto la usa -- la forma cómoda en una LAN de confianza:
#   docker run --rm -p 8417:8417 sshcryptochecker-web
#   # Cerrada con token (cada petición de /api lleva X-Auth-Token):
#   docker run --rm -p 8417:8417 -e SSH_CRYPTO_CHECKER_WEB_TOKEN=un-token sshcryptochecker-web
#
# Política propia y plugins entran por volúmenes + variables, igual que en la CLI:
#   -v $PWD/mi-politica.json:/config/algorithms.json:ro \
#   -e SSH_CRYPTO_CHECKER_CONFIG=/config/algorithms.json
#   -v $PWD/mis-plugins:/plugins:ro -e SSH_CRYPTO_CHECKER_PLUGIN_DIR=/plugins
#
# El servicio escanea lo que el contenedor alcance: publicado sin token es una
# máquina de SSRF. Úsalo en red interna o detrás de tu proxy con TLS. Para una
# exposición pública, endurece el borde:
#   -e SSH_CRYPTO_CHECKER_WEB_TOKEN=... (obliga X-Auth-Token en toda la API)
#   -e SSH_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1 (rechaza objetivos internos)
# y arranca el contenedor sin ruta a tus rangos privados (--network con egress
# controlado), que es la única garantía dura contra el SSRF.

FROM python:3.13-alpine

WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY ssh_crypto_checker/ ssh_crypto_checker/
RUN pip install --no-cache-dir . && adduser -D scc
USER scc

EXPOSE 8417
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8417/')"

CMD ["python", "-m", "ssh_crypto_checker.web", "--host", "0.0.0.0", "--port", "8417"]
