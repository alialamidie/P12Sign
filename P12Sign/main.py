from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import FileResponse
import httpx
import os
import subprocess
from uuid import uuid4

app = FastAPI()

# Directories for temporary and signed files
TEMP_DIR = "./temp"
SIGNED_DIR = "./signed"
os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

@app.get("/sign_app/")
async def sign_app(
    p12_url: str = Form(...),  # URL of the .p12 certificate
    certmobileprovision_url: str = Form(...),  # URL of the .mobileprovision file
    certpass: str = Form(...),  # Password for the .p12 certificate
    ipa_url: str = Form(...),  # URL of the .ipa file
    app_name: str = Form(...),  # Name of the app (for signed file naming)
    bundle_id: str = Form(...),  # Bundle ID of the app
):
    try:
        # Generate unique filenames for the temporary files
        p12_file = os.path.join(TEMP_DIR, f"{uuid4()}.p12")
        mobileprovision_file = os.path.join(TEMP_DIR, f"{uuid4()}.mobileprovision")
        ipa_file = os.path.join(TEMP_DIR, f"{uuid4()}.ipa")
        signed_ipa_file = os.path.join(SIGNED_DIR, f"{app_name}_signed.ipa")

        # Download the files from the provided URLs
        await download_file(p12_url, p12_file)
        await download_file(certmobileprovision_url, mobileprovision_file)
        await download_file(ipa_url, ipa_file)

        # Call macOS-specific signing process
        await sign_ipa_on_mac(p12_file, mobileprovision_file, certpass, ipa_file, signed_ipa_file)

        # Return the download link for the signed IPA file
        return {"download_link": f"/download/{os.path.basename(signed_ipa_file)}"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        # Clean up temporary files after processing
        for file in [p12_file, mobileprovision_file, ipa_file]:
            if os.path.exists(file):
                os.remove(file)

@app.get("/download/{filename}")
async def download_signed_ipa(filename: str):
    # Serve the signed IPA file for download
    file_path = os.path.join(SIGNED_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="application/octet-stream", filename=filename)
    else:
        raise HTTPException(status_code=404, detail="File not found")

async def download_file(url: str, dest_path: str):
    # Download the files (certificate, provisioning profile, IPA) from URLs
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            with open(dest_path, 'wb') as file:
                for chunk in response.iter_bytes():
                    if chunk:
                        file.write(chunk)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error downloading file: {e}")

async def sign_ipa_on_mac(p12_file: str, mobileprovision_file: str, certificate_password: str, ipa_file: str, signed_ipa_file: str):
    # Sign the IPA file on a macOS system
    try:
        keychain = os.path.join(TEMP_DIR, f"{uuid4()}.keychain")
        password = certificate_password

        # Import the P12 certificate into macOS keychain
        subprocess.run(
            ["security", "import", p12_file, "-k", keychain, "-P", password, "-T", "/usr/bin/codesign", "-T", "/usr/bin/xcrun"],
            check=True
        )

        # Use xcrun to sign the IPA file
        subprocess.run(
            [
                "xcrun", "altool", "--sign", "iphone", "--input", ipa_file, "--output", signed_ipa_file,
                "--provisioning-profile", mobileprovision_file
            ],
            check=True
        )

        # Clean up the temporary keychain after signing
        os.remove(keychain)

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Signing process failed: {e}")
