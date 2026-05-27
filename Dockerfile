FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLAG="QA{r3d4ct3d}"
ENV MAX_QUERIES="10000"
ENV PORT="10001"

EXPOSE 10001

CMD ["python", "server.py"]
