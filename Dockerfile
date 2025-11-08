# Use a lightweight Python image
FROM python:3.13-slim

# Install libmagic system library
RUN apt-get update && apt-get install -y libmagic1

# Set workdir
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Command to run FastAPI app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
