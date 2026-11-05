# recon-dash

recon-dash is a Dockerized dashboard for importing and reviewing subdomain results. It does not enumerate domains, probe hosts, or make network requests to any domain in an import.

## Quick start

1. Copy `.env.example` to `.env`.
2. Set `MYSQL_PASSWORD` and `MYSQL_ROOT_PASSWORD` to strong, unique values. Set `APP_TOKEN` to a separate long random value.
3. Run `make up`.
4. Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and enter the API token in the dashboard.

The host port is bound to `127.0.0.1`. The container refuses to start on a wildcard interface without `APP_TOKEN`. MySQL is not published to the host. Scan records persist in the named MySQL volume; raw imports and summaries persist in the `recon_data` volume under `/data/<domain>/<scan_id>/`.

## Import format

Upload one UTF-8 `.json` or `.csv` file and enter the domain it belongs to. JSON example:

```json
{
  "subdomains": [
    {"name": "www.example.com", "sources": ["crt.sh", "assetfinder"]},
    "api.example.com"
  ],
  "live_hosts": [
    {"url": "https://www.example.com", "host": "www.example.com", "status_code": 200, "title": "Example"}
  ]
}
```

CSV requires a `name` column. A `sources` column is optional. Out-of-scope names and live-host URLs are discarded; names are lowercased, wildcard prefixes are removed, and duplicates are merged. Uploads are limited to 5 MB and 10,000 rows. The API accepts `Authorization: Bearer <APP_TOKEN>` when `APP_TOKEN` is configured.

## Dashboard features

- Search and sort imported subdomains, view source counts, and see which names were supplied as live.
- Browse imports by domain and compare two imports for new, removed, and unchanged names.
- Export a scan as JSON or CSV, or download a Markdown report.
- Keep the raw upload and a normalized `summary.json` alongside database records.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/import` | Multipart form fields `domain` and `file` |
| `GET` | `/api/domains` | List domains with imported records |
| `GET` | `/api/scans?domain=example.com` | List imports, newest first |
| `GET` | `/api/scans/{id}` | Read one import |
| `GET` | `/api/scans/{id}/diff?compare_to={id}` | Compare imports for the same domain |
| `GET` | `/api/scans/{id}/export?format=json\|csv` | Download normalized results |
| `GET` | `/api/scans/{id}/report` | Download a Markdown report |
| `GET` | `/health` | Container health check |

## Passive and active data

Imported data may include findings gathered elsewhere. recon-dash itself performs neither passive collection (such as certificate-transparency lookups) nor active testing (such as brute-force enumeration or HTTP probing). A domain entry is only used to validate and scope the uploaded file. The report states that host availability has not been independently verified.

Use only data you are authorized to handle. Keep the token and database credentials private, and do not expose this service publicly without a deliberate authenticated deployment configuration.

## Development and tests

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
PATH=".venv/bin:$PATH" make test
```

# subdomain-recon-pipeline