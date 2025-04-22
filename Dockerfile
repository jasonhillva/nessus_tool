FROM python:3.9-slim

WORKDIR /app

# Copy the current directory contents into the container
COPY . /app/

# Install dependencies
RUN pip install --no-cache-dir -e .

# Create directories for uploads and other data
RUN mkdir -p /app/nessus_scans /app/nessus_csv /app/uploads

# Make port 5000 available for the web interface
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=web_app.py
ENV UPLOAD_FOLDER=/app/uploads

# Run the application with web interface by default
ENTRYPOINT ["python", "-m", "nessus_tool"]
CMD ["web", "--host", "0.0.0.0", "--port", "5000"]