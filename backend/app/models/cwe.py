from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base
from sqlalchemy.orm import relationship

class CWE(Base):

    __tablename__ = "cwes"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    common_consequenses = Column(Text, nullable=True)
    potential_mitigations = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    
    capec_relations = relationship(
        "CWECAPECRelation",
        back_populates="cwe",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    cve_relations = relationship(
        "CVECWERelation",
        back_populates="cwe",
        cascade="all, delete-orphan",
        passive_deletes=True
    )