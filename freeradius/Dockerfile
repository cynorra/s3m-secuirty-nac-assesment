FROM freeradius/freeradius-server:latest-3.2

# ── Sorun yaratan varsayılan dosyaları kaldır ──────────────────
RUN rm -f /etc/freeradius/sites-enabled/inner-tunnel \
    && rm -f /etc/freeradius/sites-enabled/default \
    && rm -f /etc/freeradius/mods-enabled/eap

# ── Kendi config dosyalarımızı kopyala ─────────────────────────
COPY clients.conf /etc/freeradius/clients.conf
COPY mods-enabled/rest /etc/freeradius/mods-enabled/rest
COPY sites-enabled/default /etc/freeradius/sites-enabled/default

# ── Test araçları ──────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# ── Dosya izinleri ─────────────────────────────────────────────
RUN chown freerad:freerad /etc/freeradius/clients.conf \
        /etc/freeradius/mods-enabled/rest \
        /etc/freeradius/sites-enabled/default \
    && chmod 640 /etc/freeradius/clients.conf \
        /etc/freeradius/mods-enabled/rest \
        /etc/freeradius/sites-enabled/default
