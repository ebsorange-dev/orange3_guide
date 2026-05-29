FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# HTTP 통신 (HTTPS 비활성화)
# 주의: showSaveFilePicker(File System Access API)는 secure context(HTTPS or localhost) 필요
#       → HTTP + 비-localhost IP 접속 시 자동으로 anchor 다운로드 폴백 사용
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
