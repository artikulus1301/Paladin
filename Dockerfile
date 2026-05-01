FROM python:3.11-slim

WORKDIR /app

# System deps for SpaCy + lxml
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download SpaCy models (multilingual + English)
RUN python -m spacy download en_core_web_sm && \
    python -m spacy download ru_core_news_sm && \
    python -m spacy download xx_ent_wiki_sm

COPY app/ ./app/
COPY config/ ./config/

RUN mkdir -p /app/logs

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

CMD ["python", "-m", "app.main"]
