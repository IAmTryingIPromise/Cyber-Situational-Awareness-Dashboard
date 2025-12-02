from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from sqlalchemy.sql import func
from app.database import Base
from sqlalchemy.orm import relationship

class CVE(Base):

    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    cvss = Column(Float, nullable=True)
    exploitability = Column(Float, nullable=True)
    impact = Column(Float, nullable=True)
    epss = Column(Float, nullable=True)
    risk_level = Column(Float, default=.0)
    impact_score = Column(Float, nullable=True)
    exploitability_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    asset_relations = relationship(
        "AssetCVERelation",
        back_populates="cve",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    cwe_relations = relationship(
        "CVECWERelation",
        back_populates="cve",
        cascade="all, delete-orphan",
        passive_deletes=True
    )