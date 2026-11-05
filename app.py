"""Import-only API for storing and comparing user-supplied recon results."""

import csv
import io
import ipaddress
import json
import os
import re
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, create_engine, select
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


if os.getenv("DB_HOST"):
    database_url = URL.create(
        "mysql+pymysql",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ["DB_HOST"],
        port=int(os.getenv("DB_PORT", "3306")),
        database=os.environ["DB_NAME"],
    )
else:
    database_url = os.getenv("DATABASE_URL", "sqlite:///./recon-dash.db")
DATA_DIR = Path(os.getenv("DATA_DIR", "./data")).resolve()
APP_TOKEN = os.getenv("APP_TOKEN", "")
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_ROWS = 10000
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

engine_options = {"pool_pre_ping": True}
if str(database_url).startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(database_url, **engine_options)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(253), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    scans: Mapped[list["Scan"]] = relationship(back_populates="domain")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_domain_started", "domain_id", "started_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="complete", nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[Domain] = relationship(back_populates="scans")
    subdomains: Mapped[list["Subdomain"]] = relationship(
        foreign_keys="Subdomain.scan_id", cascade="all, delete-orphan"
    )
    live_hosts: Mapped[list["LiveHost"]] = relationship(cascade="all, delete-orphan")
    stage_runs: Mapped[list["StageRun"]] = relationship(cascade="all, delete-orphan")


class StageRun(Base):
    __tablename__ = "stage_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    stage: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    count: Mapped[int] = mapped_column(Integer, default=0)
    log_tail: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("scan_id", "name", name="uq_subdomain_scan_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    first_seen_scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)


class LiveHost(Base):
    __tablename__ = "live_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)


class Screenshot(Base):
    __tablename__ = "screenshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)


@asynccontextmanager
async def lifespan(_: FastAPI):
    host = os.getenv("APP_BIND_HOST", "127.0.0.1")
    if host in {"0.0.0.0", "::"} and not APP_TOKEN:
        raise RuntimeError("APP_TOKEN is required when binding to a public interface")
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="recon-dash", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


def get_db():
    with SessionLocal() as db:
        yield db


def require_token(authorization: str | None = Header(default=None)) -> None:
    if not APP_TOKEN:
        return
    expected = f"Bearer {APP_TOKEN}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="A valid bearer token is required")


def validate_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("Enter a fully qualified domain name, such as example.com")
    if domain == "localhost" or domain.endswith((".localhost", ".internal", ".local")):
        raise ValueError("Local and internal domains are not accepted")
    try:
        address = ipaddress.ip_address(domain)
    except ValueError:
        address = None
    if address and (not address.is_global):
        raise ValueError("Private or non-public IP addresses are not accepted")
    return domain


def in_scope(name: str, domain: str) -> bool:
    normalized = name.strip().lower().removeprefix("*.").rstrip(".")
    return normalized == domain or normalized.endswith(f".{domain}")


def merge_subdomains(values: list[dict], domain: str) -> list[dict]:
    merged: dict[str, set[str]] = {}
    for item in values:
        raw_name = item.get("name", "")
        if not isinstance(raw_name, str):
            continue
        name = raw_name.strip().lower().removeprefix("*.").rstrip(".")
        if not in_scope(name, domain):
            continue
        sources = item.get("sources", ["import"])
        if isinstance(sources, str):
            sources = [sources]
        if not isinstance(sources, list):
            sources = ["import"]
        merged.setdefault(name, set()).update(
            source.strip()[:80] for source in sources if isinstance(source, str) and source.strip()
        )
        if not merged[name]:
            merged[name].add("import")
    return [{"name": name, "sources": sorted(sources)} for name, sources in sorted(merged.items())]


def parse_upload(contents: bytes, filename: str, domain: str) -> tuple[list[dict], list[dict]]:
    if len(contents) > MAX_UPLOAD_BYTES:
        raise ValueError("The upload exceeds the 5 MB limit")
    suffix = Path(filename).suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(contents)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("The JSON file could not be parsed") from error
        if not isinstance(data, dict):
            raise ValueError("JSON must contain an object with a subdomains list")
        rows = data.get("subdomains", [])
        host_rows = data.get("live_hosts", [])
    elif suffix == ".csv":
        try:
            rows = list(csv.DictReader(io.StringIO(contents.decode("utf-8-sig"))))
        except UnicodeDecodeError as error:
            raise ValueError("The CSV file must use UTF-8 encoding") from error
        host_rows = []
    else:
        raise ValueError("Upload a .json or .csv file")
    if not isinstance(rows, list) or not isinstance(host_rows, list):
        raise ValueError("The subdomains and live_hosts fields must be lists")
    if len(rows) + len(host_rows) > MAX_ROWS:
        raise ValueError("The upload contains more than 10,000 rows")

    subdomains = []
    for row in rows:
        if isinstance(row, str):
            subdomains.append({"name": row})
        elif isinstance(row, dict):
            subdomains.append(row)
    merged = merge_subdomains(subdomains, domain)

    live_hosts = []
    for row in host_rows:
        if not isinstance(row, dict):
            continue
        url = row.get("url", "")
        host = row.get("host", "")
        if not isinstance(url, str) or not isinstance(host, str):
            continue
        parsed = urlsplit(url)
        host = host.strip().lower().removeprefix("*.").rstrip(".")
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            continue
        if (not in_scope(host, domain) or parsed.hostname is None
            or not in_scope(parsed.hostname, domain) or host != parsed.hostname.lower()):
            continue
        try:
            status_code = int(row["status_code"]) if row.get("status_code") not in (None, "") else None
        except (TypeError, ValueError):
            status_code = None
        if status_code is not None and not 100 <= status_code <= 599:
            status_code = None
        live_hosts.append({
            "url": url[:2048],
            "host": host,
            "status_code": status_code,
            "title": str(row.get("title", ""))[:512] or None,
        })
    return merged, live_hosts


def as_dict(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "domain": scan.domain.name,
        "status": scan.status,
        "started_at": scan.started_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "subdomains": [
            {"name": row.name, "sources": row.sources if isinstance(row.sources, list) else json.loads(row.sources),
             "first_seen_scan_id": row.first_seen_scan_id}
            for row in sorted(scan.subdomains, key=lambda row: row.name)
        ],
        "live_hosts": [
            {"url": row.url, "host": row.host, "status_code": row.status_code, "title": row.title}
            for row in scan.live_hosts
        ],
    }


@app.get("/", include_in_schema=False)
def dashboard_page():
    return FileResponse("static/index.html")


@app.get("/history", include_in_schema=False)
def history_page():
    return FileResponse("static/history.html")


@app.get("/api/domains", dependencies=[Depends(require_token)])
def list_domains(db: Session = Depends(get_db)):
    return [{"name": name} for name in db.scalars(select(Domain.name).order_by(Domain.name)).all()]


@app.get("/api/scans", dependencies=[Depends(require_token)])
def list_scans(domain: str | None = None, db: Session = Depends(get_db)):
    query = select(Scan).join(Domain).order_by(Scan.started_at.desc())
    if domain:
        try:
            domain = validate_domain(domain)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        query = query.where(Domain.name == domain)
    return [{"id": scan.id, "domain": scan.domain.name, "status": scan.status,
             "started_at": scan.started_at.isoformat(), "count": len(scan.subdomains)}
            for scan in db.scalars(query).all()]


@app.post("/api/import", status_code=201, dependencies=[Depends(require_token)])
async def import_results(
    domain: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    try:
        domain = validate_domain(domain)
        contents = await file.read(MAX_UPLOAD_BYTES + 1)
        subdomains, live_hosts = parse_upload(contents, file.filename or "", domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    db_domain = db.scalar(select(Domain).where(Domain.name == domain))
    if db_domain is None:
        db_domain = Domain(name=domain)
        db.add(db_domain)
        db.flush()

    scan_id = str(uuid.uuid4())
    scan = Scan(id=scan_id, domain=db_domain, status="complete")
    db.add(scan)
    db.flush()
    names = [item["name"] for item in subdomains]
    previously_seen = {}
    if names:
        prior_rows = db.execute(
            select(Subdomain.name, Subdomain.first_seen_scan_id)
            .join(Scan, Scan.id == Subdomain.scan_id)
            .where(Scan.domain_id == db_domain.id, Subdomain.name.in_(names))
            .order_by(Scan.started_at.asc())
        ).all()
        previously_seen = {name: first_seen for name, first_seen in reversed(prior_rows)}
    for item in subdomains:
        name = item["name"]
        db.add(Subdomain(scan_id=scan_id, name=name, sources=item["sources"],
                         first_seen_scan_id=previously_seen.get(name) or scan_id))
    for item in live_hosts:
        db.add(LiveHost(scan_id=scan_id, **item))
    db.add(StageRun(scan_id=scan_id, stage="import", status="complete", count=len(subdomains),
                    log_tail=f"Imported {len(subdomains)} subdomains and {len(live_hosts)} live hosts"))
    db.commit()
    db.refresh(scan)

    scan_dir = DATA_DIR / domain / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "raw.json").write_bytes(contents)
    (scan_dir / "summary.json").write_text(json.dumps(as_dict(scan), indent=2), encoding="utf-8")
    return {"id": scan_id, "domain": domain, "status": "complete", "subdomains": len(subdomains),
            "live_hosts": len(live_hosts)}


@app.get("/api/scans/{scan_id}", dependencies=[Depends(require_token)])
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return as_dict(scan)


@app.get("/api/scans/{scan_id}/diff", dependencies=[Depends(require_token)])
def scan_diff(scan_id: str, compare_to: str, db: Session = Depends(get_db)):
    current = db.get(Scan, scan_id)
    previous = db.get(Scan, compare_to)
    if current is None or previous is None:
        raise HTTPException(status_code=404, detail="One or both scans were not found")
    if current.domain_id != previous.domain_id:
        raise HTTPException(status_code=400, detail="Scans must belong to the same domain")
    current_names = {row.name for row in current.subdomains}
    previous_names = {row.name for row in previous.subdomains}
    return {"new": sorted(current_names - previous_names), "removed": sorted(previous_names - current_names),
            "unchanged": sorted(current_names & previous_names)}


@app.get("/api/scans/{scan_id}/export", dependencies=[Depends(require_token)])
def export_scan(scan_id: str, format: str = "json", db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = as_dict(scan)
    if format == "json":
        return Response(json.dumps(data, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}.json"'})
    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["name", "sources", "live", "status_code", "url"])
        hosts = {host.host: host for host in scan.live_hosts}
        for item in data["subdomains"]:
            live = hosts.get(item["name"])
            writer.writerow([item["name"], ",".join(item["sources"]), bool(live),
                             live.status_code if live else "", live.url if live else ""])
        return Response(output.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}.csv"'})
    raise HTTPException(status_code=400, detail="format must be csv or json")


@app.get("/api/scans/{scan_id}/report", response_class=PlainTextResponse,
         dependencies=[Depends(require_token)])
def scan_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    lines = [f"# Imported results: {scan.domain.name}", "", f"- Scan: `{scan.id}`",
             f"- Imported: {scan.started_at.isoformat()}", "", "## Results", "",
             f"- Subdomains: {len(scan.subdomains)}", f"- Live hosts supplied: {len(scan.live_hosts)}",
             "", "## Data source and boundaries", "",
             "This report contains only user-imported data. recon-dash did not contact the domain "
             "or verify the reachability of listed hosts.", "", "## Subdomains", ""]
    lines.extend(f"- {row.name} (sources: {', '.join(row.sources) if isinstance(row.sources, list) else row.sources})"
                 for row in sorted(scan.subdomains, key=lambda row: row.name))
    return "\n".join(lines) + "\n"


@app.get("/health")
def health():
    return {"status": "ok"}