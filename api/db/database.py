import os
import json
import sqlite3
import psycopg
from typing import Dict, Any, List, Optional
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

def get_db():
    if DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://"):
        return psycopg.connect(DATABASE_URL)
    else:
        db_path = os.getenv("SQLITE_DB_PATH", "sentinelgraph_sim.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS simulations (
                id VARCHAR(100) PRIMARY KEY,
                scenario_id VARCHAR(50) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
                current_tick INT NOT NULL DEFAULT 0,
                threat_score INT NOT NULL DEFAULT 0,
                severity VARCHAR(20) NOT NULL DEFAULT 'LOW',
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL
            );
        """)

        # Migration helper for existing SQLite/Postgres DBs from earlier steps
        try:
            if "sqlite3" in str(type(conn)).lower():
                cursor.execute("PRAGMA table_info(simulations)")
                cols = [row[1] for row in cursor.fetchall()]
                if "threat_score" not in cols:
                    cursor.execute("ALTER TABLE simulations ADD COLUMN threat_score INT NOT NULL DEFAULT 0")
                if "severity" not in cols:
                    cursor.execute("ALTER TABLE simulations ADD COLUMN severity VARCHAR(20) NOT NULL DEFAULT 'LOW'")
            elif "psycopg" in str(type(conn)).lower() or "postgresql" in str(type(conn)).lower():
                cursor.execute("""
                    ALTER TABLE simulations ADD COLUMN IF NOT EXISTS threat_score INT NOT NULL DEFAULT 0;
                    ALTER TABLE simulations ADD COLUMN IF NOT EXISTS severity VARCHAR(20) NOT NULL DEFAULT 'LOW';
                """)
        except Exception as mig_err:
            print(f"[init_db] Migration check notice: {mig_err}")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id VARCHAR(50) NOT NULL,
                simulation_id VARCHAR(100) NOT NULL,
                hostname VARCHAR(100) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                host_type VARCHAR(50) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'HEALTHY',
                criticality VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
                updated_at VARCHAR(50) NOT NULL,
                PRIMARY KEY (id, simulation_id)
            );
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id VARCHAR(100) PRIMARY KEY,
                simulation_id VARCHAR(100) NOT NULL,
                timestamp VARCHAR(50) NOT NULL,
                source_ip VARCHAR(45) NOT NULL,
                target_host VARCHAR(50) NOT NULL,
                event_type VARCHAR(100) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                details TEXT NOT NULL,
                created_at VARCHAR(50) NOT NULL
            );
        """)
        
        conn.commit()
    finally:
        conn.close()

# Auto-initialize database tables on module load
init_db()
