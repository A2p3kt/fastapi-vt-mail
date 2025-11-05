# Using Fast API
from fastapi import (
    FastAPI,
    HTTPException,
    Form,
    File,
    UploadFile,
    BackgroundTasks,
    Header,
    Depends,
)
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio  # For handling async concurrency
import os  # For environment variables
from io import BytesIO
from dotenv import load_dotenv  # To load .env file
from typing import List, Any
import vt  # VirusTotal's python library
from pathlib import Path  # handle getting the extension
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid  # for unique file names
import magic
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail,
    Attachment,
    FileContent,
    FileName,
    FileType,
    Disposition,
    From,
)
import base64 # for handling the attachments

# Load environment variables
load_dotenv()

# Allowed types
ALLOWED_MIME_TYPES = [
    "application/pdf",
    "image/jpeg",
    "image/png",
    "application/step",
    "application/step-file",
    "application/x-step",
    "model/step",
    "model/stp",
]

ALLOWED_EXTENSIONS = [".pdf", ".jpeg", ".jpg", ".png", ".step", ".stp"]

MAX_FILE_SIZE = 10 * 1024 * 1024

MAX_FILES = 3

# Setting up VirusTotal library
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

API_KEY = os.getenv("FAST_API_KEY")

origin = os.getenv("ALLOWED_ORIGIN").split(",")

client = vt.Client(VT_API_KEY)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origin,
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["*"],
)


# Checks that the call is valid
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized Call")


# -----------------------------------------------
# 1. Receive the POST request from the front end
# -----------------------------------------------
@app.post("/submit-form", dependencies=[Depends(verify_api_key)])
async def handle_submission(
    background_tasks: BackgroundTasks,
    name: str = Form(...),
    email: str = Form(...),
    company: str = Form(...),
    phone: str = Form(...),
    material: str = Form(...),
    quantity: str = Form(...),
    description: str = Form(...),
    blueprints: List[UploadFile] = File(None),
):
    # Ensure that blueprint is an iterable list
    blueprints = [] if not blueprints else blueprints

    # Check the number of files attached
    if len(blueprints) > MAX_FILES:
        raise HTTPException(status_code=400, detail="Maximum of 3 files allowed")

    processed_files = []

    for blueprint in blueprints:
        # 1. First check to verify the file type
        if blueprint.content_type not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=400, detail=f"{blueprint.filename} is not supported"
            )

        # 2. Checking the file extension to verify the file type
        ext = Path(blueprint.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400, detail=f"{ext} is not a supported extension"
            )

        file_content = await blueprint.read()

        # 3. Final check using the magic numbers.
        head = file_content[:2048]  # the first 2KB to check for the file signature
        mime_type = magic.from_buffer(head, mime=True)
        if mime_type not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=400, detail=f"Invalid file type: {mime_type}"
            )

        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"{blueprint.filename} is bigger than expected: Max size = 10MB",
            )

        # Sanitizing the filename to ensure it is unique and safe
        filename = secure_filename(blueprint.filename)
        filename = "attachment" if not filename else filename

        timestamp = datetime.now().strftime("%Y%m%d%H%M")

        filename = f"{timestamp}_{uuid.uuid4().hex}_{filename}"

        processed_files.append(
            {
                "filename": filename,
                "file_content": file_content,
                "mime_type": blueprint.content_type,
                "is_clean": None,
            }
        )

        await blueprint.close()

    customer_data = {
        "name": name,
        "email": email,
        "phone": phone,
        "company": company,
        "material": material,
        "quantity": quantity,
        "description": description,
    }

    # Crucial Step: Add the VirusTotal scan and Email function to background tasks
    # This allows the API to return an immediate success response to the user
    # while the time-consuming tasks (VT scan, polling, email send) run in the background.
    background_tasks.add_task(send_customer_email, customer_data, processed_files)

    return JSONResponse(
        status_code=200,
        content={
            "message": "Form submitted successfully. Files are being scanned and email will be sent shortly."
        },
    )


# -----------------------------------------------
# 2. VirusTotal API Logic
# -----------------------------------------------
async def submit_to_virustotal(file_data: dict[str, Any]):
    file_obj = BytesIO(file_data["file_content"])
    file_obj.name = file_data["filename"]

    print(f"Beginning to scan {file_obj.name}")

    try:
        analysis = await client.scan_file_async(file_obj, wait_for_completion=True)
        stats = analysis.stats
        is_clean = stats.get("malicious", 0) == 0
        file_data["is_clean"] = is_clean
    except vt.APIError as e:
        print(f"VirusTotal scan failed for {file_obj.name}: {e}")
        pass
    finally:
        print(f"Finished scan on {file_obj.name}")
        file_obj.close()

    return file_data


# -----------------------------------------------
# 3. Email sending logic (Background Task)
# -----------------------------------------------
async def send_customer_email(
    customer_info: dict[str, str], files_to_process: List[dict[str, Any]]
):

    # for async concurrency
    scanned_files = await asyncio.gather(
        *[submit_to_virustotal(file) for file in files_to_process]
    )

    clean_attachments = []
    unscanned_files = []  # where VirusTotal failed to scan
    redacted_files = []  # where files where deemed malicious

    for file in scanned_files:
        if file["is_clean"]:
            # Add file as attachment
            clean_attachments.append(file)
        elif file["is_clean"] is None:
            unscanned_files.append(file)
        else:
            redacted_files.append(file["filename"])

    # Construct the email body text
    redaction_note = ""
    if redacted_files:
        redaction_note = (
            f"<p style='color:red; font-weight:bold;'>🚨 ATTENTION: The following file(s) "
            f"were REDACTED due to a failed VirusTotal scan (potential malware detected): "
            f"{', '.join(redacted_files)}.</p>"
        )

    unscanned_note = ""
    if unscanned_files:
        unscanned_note = (
            f"<p style='color:orange; font-weight:bold;'>⚠️ The following file(s) "
            f"could not be scanned due to a VirusTotal error or connectivity issue: "
            f"{', '.join(f['filename'] for f in unscanned_files)}.</p>"
        )

    disclaimer = "<p style='font-size:small; color:gray;'>This email contains customer submission information. Please handle with care.</p>"

    email_body = f"""
    {disclaimer}
    {unscanned_note}
    {redaction_note}

    <h3>Customer Submission</h3>

    <p><strong>Email:</strong> {customer_info['email']}<br>
    <strong>Name:</strong> {customer_info['name']}<br>
    <strong>Phone:</strong> {customer_info['phone']}<br>
    <strong>Company:</strong> {customer_info['company']}<br>
    <strong>Material:</strong> {customer_info['material']}<br>
    <strong>Quantity:</strong> {customer_info['quantity']}</p>

    <h4>Description</h4>
    <p>{customer_info['description']}</p>
    """

    # Prepare attachments
    attachments = []
    for f in clean_attachments + unscanned_files:

        encoded_content = base64.b64encode(f["file_content"]).decode()

        attachments.append(
            Attachment(
                file_content=FileContent(encoded_content),
                file_name=FileName(f["filename"]),
                file_type=FileType(f["mime_type"]),
                disposition=Disposition("attachment"),
            )
        )

    # Send the Email
    message = Mail(
        from_email=From(os.getenv("MAIL_FROM"), os.getenv("MAIL_FROM_NAME")),
        to_emails=os.getenv("RECIPIENT_EMAIL"),
        subject="New Customer Submission",
        html_content=email_body,
    )

    for attachment in attachments:
        message.add_attachment(attachment)

    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        response = sg.send(message)
        print(response.status_code)
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")
