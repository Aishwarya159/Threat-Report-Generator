import os
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import fitz # PyMuPDF
import shutil
import tempfile
import sqlite3
from typing import List, Optional
from starlette.background import BackgroundTasks
from pydantic import BaseModel, Field, ValidationError
import datetime
import uuid

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Query
from sqlalchemy import Column, String, Text, ForeignKey, DateTime, JSON, create_engine
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from fastapi_filter.contrib.sqlalchemy import Filter

from pydantic import BaseModel, Field
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

# -----------------------
# AI Agent Config
# -----------------------
os.environ["OPENROUTER_API_KEY"] = "" # Add openrouter API key here (If using openai API intead, change the base url in the below line)
openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
provider = OpenAIProvider(api_key=openrouter_api_key, base_url="https://openrouter.ai/api/v1")
model = OpenAIChatModel("nvidia/nemotron-nano-9b-v2", provider=provider) #Can change the model here

# -----------------------
# Database Setup
# -----------------------
DATABASE_URL = "sqlite:///./threat_metadata.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# -----------------------
# ORM Models
# -----------------------
class PDFDocument(Base):
    __tablename__ = "pdf_documents"
    id = Column(String, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    upload_at = Column(DateTime)
    processed_at = Column(DateTime)

    cves = relationship("CVERecord", back_populates="pdf")
    actors = relationship("ThreatActorRecord", back_populates="pdf")


class CVERecord(Base):
    __tablename__ = "cves"
    id = Column(String, primary_key=True, index=True)
    pdf_id = Column(String, ForeignKey("pdf_documents.id"))
    cve_id = Column(String)
    description = Column(Text)
    severity = Column(String)
    extracted_at = Column(DateTime)

    pdf = relationship("PDFDocument", back_populates="cves")


class ThreatActorRecord(Base):
    __tablename__ = "threat_actors"
    id = Column(String, primary_key=True, index=True)
    pdf_id = Column(String, ForeignKey("pdf_documents.id"))
    name = Column(String)
    aliases = Column(JSON)
    description = Column(Text)
    extracted_at = Column(DateTime)

    pdf = relationship("PDFDocument", back_populates="actors")


# Create tables
Base.metadata.create_all(bind=engine)

# -----------------------
# Filters
# -----------------------
class PDFDocumentFilter(Filter):
    filename__ilike: Optional [str] | None
    upload_at__gte: Optional [datetime.datetime] | None
    upload_at__lte: Optional [datetime.datetime] | None

    class Constants(Filter.Constants):
        model = PDFDocument


class CVEJoinedFilter(Filter):
    cve_id: Optional [str] | None
    severity: Optional [str] | None
    pdf: Optional [PDFDocumentFilter] | None

    class Constants(Filter.Constants):
        model = CVERecord


class ThreatActorJoinedFilter(Filter):
    name: str | None
    description__ilike: str | None
    pdf: PDFDocumentFilter | None

    class Constants(Filter.Constants):
        model = ThreatActorRecord

# -----------------------
# Dependency
# -----------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -----------------------
# AI Agent Setup
# -----------------------
class ThreatActor(BaseModel):
    name: str = Field(...,description="Name of the threat actor mentioned in the text")
    aliases: Optional[ List[str]] = Field(...,description="Aliases of the threat actor")
    description: str = Field(...,description="Descripton of the threat actor")

class CVE(BaseModel):
    cve_id: str = Field(..., pattern=r'CVE-\d{4}-\d{5}')
    description: str = Field(...,description="Descripton of the CVE")
    severity: str = Field(...,description="Severity of the CVE")

class CyberThreatReport(BaseModel):
    """A structured report summarizing cyber threat information."""
    cves: Optional[List[CVE]] = Field(..., description="A list of CVEs mentioned in the text.")

class CyberThreatActors(BaseModel):
    """A structured report summarizing cyber threat information."""
    threat_actors: Optional[List[ThreatActor]] = Field(..., description="A list of threat actors mentioned in the text.")



cve_agent = Agent(
    model,
    output_type=CyberThreatReport,
    name="CVE Extractor",
    system_prompt="""Your task is to extract a list of CVEs from the provided text and find their description and severity from the web.
    Output the extracted information in JSON format."""
)

actor_agent = Agent(
    model,
    output_type=CyberThreatActors,
    name="Actor Extractor",
    system_prompt="""You are a cyber threat intelligence expert. Your task is to extract a list of threat actors from the provided text and find it's description and every known alias of it from the web.
    Output the extracted information in JSON format. """
)

# -----------------------
# Utilities
# -----------------------
def extract_text_from_pdf(file_path: str):
    text_content = ""
    with fitz.open(file_path) as pdf_doc:
        for page in pdf_doc:
            text_content += page.get_text()
    return text_content


def cleanup(file_path: str):
    os.remove(file_path)

# -----------------------
# FastAPI App
# -----------------------
app = FastAPI()

# -----------------------
# Upload PDF
# -----------------------
@app.post("/upload-pdf/")
async def upload_pdf(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are supported")

    upload_timestamp = datetime.datetime.now()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_file:
        shutil.copyfileobj(file.file, temp_file)
        temp_file_path = temp_file.name

    background_tasks.add_task(cleanup, temp_file_path)

    extracted_text = extract_text_from_pdf(temp_file_path)

    try:
        cve_result = await cve_agent.run(extracted_text)
        cve_report: CyberThreatReport = cve_result.output
        print(cve_report)
        actor_result = await actor_agent.run(extracted_text)
        actor_report: CyberThreatActors = actor_result.output

        processed_timestamp = datetime.datetime.now()
        pdf_uuid = str(uuid.uuid4())

        db = SessionLocal()
        pdf_entry = PDFDocument(
            id=pdf_uuid,
            filename=file.filename,
            upload_at=upload_timestamp,
            processed_at=processed_timestamp,
        )
        db.add(pdf_entry)
        print(actor_report)
        if cve_report.cves:
            for cve in cve_report.cves:
                db.add(CVERecord(
                    id=str(uuid.uuid4()),
                    pdf_id=pdf_uuid,
                    cve_id=cve.cve_id,
                    description=cve.description,
                    severity=cve.severity,
                    extracted_at=processed_timestamp
                ))

        if actor_report.threat_actors:
            for actor in actor_report.threat_actors:
                if actor.aliases is not None and actor.name in actor.aliases:
                    actor.aliases.remove(actor.name)
                db.add(ThreatActorRecord(
                    id=str(uuid.uuid4()),
                    pdf_id=pdf_uuid,
                    name=actor.name,
                    aliases=actor.aliases,
                    description=actor.description,
                    extracted_at=processed_timestamp
                ))

        db.commit()
        db.close()
        return {"status": "success", "pdf_id": pdf_uuid}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Processing error: {e}")


# # -----------------------
# # Query Endpoints
# # -----------------------
# @app.get("/pdfs/")
# def list_pdfs(pdf_filter: PDFDocumentFilter = FilterDepends(PDFDocumentFilter), db=Depends(get_db)):
#     return pdf_filter.filter(db.query(PDFDocument)).all()

# -----------------------
# Unified /search/ Endpoint
# -----------------------
class UnifiedSearchFilter(BaseModel):
    # Results:
    show_pdfs: bool | None = None
    show_cves: bool | None = None
    show_threat_actors: bool | None = None
    # PDF fields
    pdf_filename: str | None = None
    pdf_upload_at_gte: datetime.datetime | None = None
    pdf_upload_at_lte: datetime.datetime | None = None

    # CVE fields
    cve_id: str | None = None
    cve_severity: str | None = None
    cve_description: str | None = None

    # Threat Actor fields
    actor_name: str | None = None
    actor_description: str | None = None
    actor_alias: str | None = None



@app.get("/search/")
def unified_search(filter: UnifiedSearchFilter = Depends(), db=Depends(get_db)):
    results = {}

    # PDFs
    if filter.show_pdfs:
        pdf_query = db.query(PDFDocument)
        if filter.pdf_filename:
            pdf_query = pdf_query.filter(PDFDocument.filename.ilike(f"%{filter.pdf_filename}%"))
        if filter.pdf_upload_at_gte:
            pdf_query = pdf_query.filter(PDFDocument.upload_at >= filter.pdf_upload_at_gte)
        if filter.pdf_upload_at_lte:
            pdf_query = pdf_query.filter(PDFDocument.upload_at <= filter.pdf_upload_at_lte)
        results["pdfs"] = pdf_query.all()

    # CVEs
    if filter.show_cves:
        cve_query = db.query(CVERecord).join(PDFDocument)
        if filter.cve_id:
            cve_query = cve_query.filter(CVERecord.cve_id.ilike(f"%{filter.cve_id}%"))
        if filter.cve_severity:
            cve_query = cve_query.filter(CVERecord.severity.ilike(f"%{filter.cve_severity}%"))
        if filter.cve_description:
            actor_query = actor_query.filter(CVERecord.description.ilike(f"%{filter.cve_description}%"))
        if filter.pdf_filename:
            cve_query = cve_query.filter(PDFDocument.filename.ilike(f"%{filter.pdf_filename}%"))
        results["cves"] = cve_query.all()

    # Threat Actors
    if filter.show_threat_actors:
        actor_query = db.query(ThreatActorRecord).join(PDFDocument)
        if filter.actor_name:
            actor_query = actor_query.filter(ThreatActorRecord.name.ilike(f"%{filter.actor_name}%"))
        if filter.actor_description:
            actor_query = actor_query.filter(ThreatActorRecord.description.ilike(f"%{filter.actor_description}%"))
        if filter.actor_alias:
        # Check if alias exists in JSON array
            actor_query = actor_query.filter(ThreatActorRecord.aliases.ilike(f"%{filter.actor_alias}%"))
        if filter.pdf_filename:
            actor_query = actor_query.filter(PDFDocument.filename.ilike(f"%{filter.pdf_filename}%"))
        results["threat_actors"] = actor_query.all()

    return results
