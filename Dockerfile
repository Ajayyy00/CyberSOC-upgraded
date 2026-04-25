FROM python:3.10-slim

# Create non-root user
RUN useradd -m -u 1000 user

WORKDIR /app

# Install dependencies as root so pip cache is shared
COPY ./requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy project files and set ownership
COPY . /app
RUN chmod +x /app/start.sh && chown -R user:user /app

USER user
ENV PATH="/home/user/.local/bin:$PATH"

# start.sh reads BACKEND_URL and SERVE_DASHBOARD_ONLY env vars:
#   Trainer Space  →  SERVE_DASHBOARD_ONLY unset  →  full backend (dashboard_server.py)
#   Demo Space     →  SERVE_DASHBOARD_ONLY=1      →  static dashboard only (serve_demo.py)
#                     BACKEND_URL=https://ajay00747-cybersoc-trainer.hf.space
CMD ["/bin/sh", "/app/start.sh"]
