import io
import re
import uuid
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

from cryptography.fernet import InvalidToken
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from encryption import decrypt_file, encrypt_file

app = FastAPI(title="share API")

STORAGE_DIR = Path("storage")
STORAGE_DIR.mkdir(exist_ok=True)


@app.get("/")
def home():
    return {"message": "share api is running"}


@app.post("/upload")
async def upload(file: UploadFile = File(...), password: str = Form(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="filename is missing")

    if not password:
        raise HTTPException(status_code=400, detail="password is required.")

    file_id = uuid.uuid4().hex
    destination = STORAGE_DIR / file_id

    try:
        file_bytes = await file.read()
        senitized_filename = Path(file.filename).name

        encrypted_bytes = encrypt_file(
            file_data=file_bytes, filename=senitized_filename, password=password
        )

        destination.write_bytes(encrypted_bytes)

        return {
            "message": "file encrypted and uploded successfully",
            "file_id": file_id,
        }

    except Exception:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="upload and encryption failed")
    finally:
        file.close()


@app.get("/download/{file_id}")
def download_file(file_id: str, x_password: Annotated[str, Header(alias="X-Password")]):
    if not re.fullmatch(r"[0-9a-f]{32}", file_id):
        raise HTTPException(status_code=400, detail="Invalid file OD")

    file_path = STORAGE_DIR / file_id

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="file not found")

    encrypted_data = file_path.read_bytes()

    try:
        original_filename, file_data = decrypt_file(
            encrypted_data=encrypted_data, password=x_password
        )
    except InvalidToken:
        raise HTTPException(
            status_code=401, detail="incorrect password or corrupted data."
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    safe_filename = quote(original_filename)

    headers = {"Content-Disposition": f"attachment; filename*=utf-8''{safe_filename}"}

    return StreamingResponse(
        io.BytesIO(file_data),
        media_type="application/octet-stream",
        headers=headers,
    )
