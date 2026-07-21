# Dockerfile
# ------------
# Builds an image with all Python dependencies for training and evaluating
# the model. Note: sniffer.py (live packet capture) needs raw socket access
# and root privileges that don't make sense inside a standard container -
# it is meant to run directly on the host, not through this image. This
# Dockerfile targets the reproducible, portable parts: training and
# evaluation.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default command trains the model. Override at run time for other scripts,
# e.g.: docker run <image> python show_matrix.py
CMD ["python", "train_engine.py"]
