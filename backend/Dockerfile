# backend/Dockerfile
FROM python:3.12-slim

# Set working directory inside the container
WORKDIR /app

# Set Python path to include /app
ENV PYTHONPATH=/app

# Copy the dependency list first
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your backend code (including your DB code)
COPY . .

# Expose the backend port
EXPOSE 8000

# Start the backend with Uvicorn
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
