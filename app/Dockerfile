# Placeholder build for the existing service. Hardening relevant to T2/T5:
# pinned digests, distroless (no shell/package manager), non-root numeric UID.
FROM python:3.12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS build
WORKDIR /src
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes --target /deps -r requirements.txt
COPY . .

FROM gcr.io/distroless/python3-debian12:nonroot@sha256:0000000000000000000000000000000000000000000000000000000000000000
COPY --from=build /deps /deps
COPY --from=build /src /app
ENV PYTHONPATH=/deps
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "/app/main.py"]
# NOTE: digests are placeholders; Renovate pins and bumps them in real use.
