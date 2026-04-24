FROM python:3.10-slim

# Create user with home directory
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

WORKDIR /app

# Copy requirements and install
COPY --chown=user ./requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy all environment files
COPY --chown=user . /app

# The hackathon expects the OpenEnv Server to run on 7860 for Spaces Gradio endpoints
# We will use uvicorn to host the app which complies with the spec
CMD ["uvicorn", "dashboard_server:app", "--host", "0.0.0.0", "--port", "7860"]
