FROM python:3.12-slim
RUN useradd --create-home app
USER app
WORKDIR /home/app
COPY --chown=app . .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
