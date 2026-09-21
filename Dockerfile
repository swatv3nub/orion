FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml .
COPY app ./app
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 orion
USER orion
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
