FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    curl \
    wget \
    gnupg \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libexpat1 \
    libfontconfig1 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    xdg-utils \
    chromium \
    chromium-driver \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot/package.json bot/
RUN cd bot && npm install && \
    npx puppeteer browsers install chrome

COPY server.py .
COPY templates/ templates/
COPY canvas_manager .
COPY ld-linux-x86-64.so.2 libc.so.6 ./
COPY bot/bot.js bot/

COPY flag.txt /

COPY read_flag.c .

RUN useradd -m -s /bin/bash appuser && \
    chmod 4755 canvas_manager && \
    chown root:root canvas_manager && \
    chmod +x ld-linux-x86-64.so.2 && \
    gcc -o read_flag read_flag.c && \
    chmod 4755 read_flag && \
    chown root:root read_flag && \
    chmod 400 /flag.txt && \
    chown root:root /flag.txt && \
    chown -R appuser:appuser /app && \
    chown root:root /app/canvas_manager && \
    chown root:root /app/read_flag && \
    chown root:root /flag.txt && \
    chmod +s /app/read_flag


EXPOSE 5080

COPY start.sh .
RUN chmod +x start.sh

USER appuser

CMD ["./start.sh"]

