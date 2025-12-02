from sqlalchemy import Column, Integer, ForeignKey, DateTime
from sqlalchemy.sql import func
from app.database import Base
from sqlalchemy.orm import relationship

class AssetCVERelation(Base):
    __tablename__ = "asset_cve_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)

    asset = relationship("Asset", back_populates="cve_relations")
    cve = relationship("CVE", back_populates="asset_relations")

class CVECWERelation(Base):
    __tablename__ = "cve_cwe_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    cwe_id = Column(Integer, ForeignKey("cwes.id", ondelete="CASCADE"), nullable=False)

    cve = relationship("CVE", back_populates="cwe_relations")
    cwe = relationship("CWE", back_populates="cve_relations")

class CWECAPECRelation(Base):
    __tablename__ = "cwe_capec_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(Integer, ForeignKey("cwes.id", ondelete="CASCADE"), nullable=False)
    capec_id = Column(Integer, ForeignKey("capecs.id", ondelete="CASCADE"), nullable=False)

    cwe = relationship("CWE", back_populates="capec_relations")
    capec = relationship("CAPEC", back_populates="cwe_relations")

class CAPECAttackRelation(Base):
    __tablename__ = "capec_attack_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    capec_id = Column(Integer, ForeignKey("capecs.id", ondelete="CASCADE"), nullable=False)
    attack_id = Column(Integer, ForeignKey("attacks.id", ondelete="CASCADE"), nullable=False)

    capec = relationship("CAPEC", back_populates="attack_relations")
    attack = relationship("Attack", back_populates="capec_relations")