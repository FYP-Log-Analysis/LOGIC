# Forensics API

A FastAPI-based REST API service for accessing and querying normalized Windows Event Log data for forensic analysis.

## Overview

This API serves as the backend service for the forensics log analysis system, providing RESTful endpoints to access processed and normalized Windows Event Logs. The API is containerized with Docker and uses PostgreSQL for data persistence.

## Project Structure

```
api/
├── main.py                     # Main FastAPI application entry point
├── requirements.txt            # Python dependencies
├── models/                     # Database ORM models
│   └── normalized_log.py       # SQLAlchemy model for normalized log entries
├── routes/                     # API route definitions
│   └── logs.py                 # Log-related endpoints (/api/logs)
├── scripts/                    # Utility scripts
│   └── ingest_normalized.py    # Script to ingest normalized JSON data into database
└── services/                   # Business logic layer
    └── logs_service.py         # Service layer for log data operations
```

## File Descriptions

### Core Application Files

#### `main.py`
The main FastAPI application file that:
- Sets up the FastAPI app with metadata (title, version, description)
- Configures database connection to PostgreSQL using SQLAlchemy
- Defines database session management and dependency injection
- Includes route modules (logs router)
- Provides a simple health check endpoint at the root (`/`)

#### `requirements.txt`
Lists all Python package dependencies:
- `fastapi` - Modern web framework for building APIs
- `uvicorn` - ASGI server for running FastAPI
- `sqlalchemy` - SQL toolkit and ORM
- `psycopg2-binary` - PostgreSQL adapter for Python
- `python-dotenv` - Environment variable management

### Models

#### `models/normalized_log.py`
Defines the SQLAlchemy ORM model for the `normalized_logs` table:
- **Fields**: id, timestamp, event_id, source, user_name, computer, process_path, command_line, category, summary, raw
- **Purpose**: Represents normalized Windows Event Log entries in the database
- **Indexes**: Primary key on `id`, index on `timestamp` for efficient querying

### Routes

#### `routes/logs.py`
Defines the log-related API endpoints:
- **GET `/api/logs`**: Retrieves all normalized logs from all log types
- **GET `/api/logs/{log_type}`**: Retrieves logs filtered by specific type (Application, Security, System, PowerShell_Operational)
- **Router prefix**: `/api/logs` (mounted in main.py)

### Services

#### `services/logs_service.py`
Business logic layer for log operations:
- **`load_all_logs()`**: Reads all normalized JSON files and combines them into a single response
- **`load_logs_by_type(log_type)`**: Loads logs for a specific type from the corresponding JSON file
- **Data source**: Files in `data/processed/normalized/` directory
- **Error handling**: Returns error messages for non-existent log types

### Scripts

#### `scripts/ingest_normalized.py`
Database ingestion utility script:
- **Purpose**: Loads normalized JSON log data into the PostgreSQL database
- **Function**: Bridges the gap between file-based normalized data and database storage
- **Usage**: Run to populate the database with processed log entries

## API Endpoints

### Base URL
- **Development**: `http://localhost:5000`
- **Health Check**: `GET /` - Returns API status and available routes

### Log Endpoints
- **Get All Logs**: `GET /api/logs` - Returns all normalized log entries
- **Get Logs by Type**: `GET /api/logs/{log_type}` - Returns logs for specific type

### Supported Log Types
- `Application` - Windows Application logs
- `Security` - Windows Security logs  
- `System` - Windows System logs
- `PowerShell_Operational` - PowerShell execution logs

## Database Configuration

- **Engine**: PostgreSQL 15
- **Connection String**: `postgresql://forensic:forensicpass@db:5432/fyp`
- **ORM**: SQLAlchemy with declarative base
- **Session Management**: Request-scoped sessions with automatic cleanup

## Development Setup

1. **Prerequisites**: Docker and Docker Compose
2. **Build**: `docker-compose build api`
3. **Run**: `docker-compose up -d`
4. **Access**: API available at `http://localhost:5000`
5. **Documentation**: Interactive docs at `http://localhost:5000/docs`

## Data Flow

1. Raw Windows Event Logs (.evtx) → Parser → XML format
2. XML → JSON converter → Raw JSON logs  
3. JSON → Normalizer → Standardized JSON format
4. Normalized JSON → Ingestion script → PostgreSQL database
5. Database ← API service ← Client requests

## Key Features

- **FastAPI Framework**: Automatic OpenAPI/Swagger documentation
- **Type Safety**: Pydantic models and type hints
- **Database Integration**: SQLAlchemy ORM with PostgreSQL
- **Containerized**: Docker deployment with docker-compose
- **RESTful Design**: Standard HTTP methods and status codes
- **Error Handling**: Graceful error responses for missing data
- **Performance**: Indexed database queries and efficient file operations

The API serves as the central data access layer for the forensic analysis system, providing clean, normalized access to Windows Event Log data for investigation and analysis workflows.