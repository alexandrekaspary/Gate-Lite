FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gettext && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# collectstatic não precisa dos segredos reais; usa valores de build descartáveis.
RUN DJANGO_SECRET_KEY=build-only DJANGO_DEBUG=1 python manage.py collectstatic --noinput \
    && DJANGO_SECRET_KEY=build-only DJANGO_DEBUG=1 python manage.py compilemessages

RUN chmod +x docker-entrypoint.sh && useradd --create-home --uid 1000 gatelite && chown -R gatelite:gatelite /app
USER gatelite

EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["gunicorn", "gatelite.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
