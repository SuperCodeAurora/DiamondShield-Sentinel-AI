# Use a lightweight Python Linux image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install dependencies
# We install 'curl' so the container can talk to the Ollama service
RUN apt-get update && apt-get install -y curl && pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose port 5000 (The Web Server)
EXPOSE 5000

# Run the server
CMD ["python", "demo_server.py"]
