FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt
RUN chmod +x zsign
RUN mkdir -p /app/uploads

EXPOSE 8080
CMD ["python", "app.py"]
