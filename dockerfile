FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy dependency file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your Flask app into the image
COPY application.py .

# Expose Flask default port
EXPOSE 5000

# Run the application
CMD ["python", "application.py"]

