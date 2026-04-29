import requests


API_BASE_URL = "http://127.0.0.1:8000"


def analyze_text_log(text: str) -> dict:
    response = requests.post(
        f"{API_BASE_URL}/analyze",
        json={"log": text}
    )
    response.raise_for_status()
    return response.json()


def analyze_uploaded_file(uploaded_file) -> dict:
    files = {
        "file": (
            uploaded_file.name,
            uploaded_file.getvalue(),
            "text/plain"
        )
    }

    response = requests.post(
        f"{API_BASE_URL}/analyze-file",
        files=files
    )
    response.raise_for_status()
    return response.json()