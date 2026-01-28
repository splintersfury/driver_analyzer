FROM python:3.9-slim

WORKDIR /app
RUN pip install karton-core mwdblib redis requests

COPY karton_reporter.py .

CMD ["python", "karton_reporter.py"]
