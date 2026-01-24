"""
Fixtures for end-to-end tests.

These tests run against a live backend with MinIO and Firestore emulator.
Start the services with: docker-compose -f docker-compose.e2e.yml up -d
"""
import os
import pytest
import httpx
import base64
import time
from cryptography.hazmat.primitives.asymmetric import ed25519

# Default e2e backend URL
E2E_BACKEND_URL = os.environ.get("E2E_BACKEND_URL", "http://localhost:8000")


def pytest_addoption(parser):
    """Add e2e-specific command line options"""
    parser.addoption(
        "--e2e",
        action="store_true",
        default=False,
        help="Run end-to-end tests (requires docker-compose.e2e.yml services)"
    )
    parser.addoption(
        "--e2e-url",
        action="store",
        default=E2E_BACKEND_URL,
        help=f"Backend URL for e2e tests (default: {E2E_BACKEND_URL})"
    )


def pytest_configure(config):
    """Register e2e marker"""
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end test (requires external services)"
    )


def pytest_collection_modifyitems(config, items):
    """Skip e2e tests unless --e2e flag is provided"""
    if config.getoption("--e2e"):
        # Don't skip e2e tests
        return

    skip_e2e = pytest.mark.skip(reason="Need --e2e option to run e2e tests")
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(skip_e2e)


@pytest.fixture(scope="session")
def e2e_backend_url(request):
    """Get the backend URL for e2e tests"""
    return request.config.getoption("--e2e-url")


@pytest.fixture(scope="session")
def e2e_client(e2e_backend_url):
    """
    HTTP client for e2e tests.

    Waits for the backend to be healthy before returning.
    """
    # Wait for backend to be ready
    max_retries = 30
    retry_delay = 2

    for i in range(max_retries):
        try:
            with httpx.Client(base_url=e2e_backend_url, timeout=5.0) as client:
                response = client.get("/health")
                if response.status_code == 200:
                    break
        except (httpx.ConnectError, httpx.TimeoutException):
            pass

        if i < max_retries - 1:
            time.sleep(retry_delay)
    else:
        pytest.fail(
            f"Backend at {e2e_backend_url} not healthy after {max_retries * retry_delay}s. "
            "Make sure docker-compose.e2e.yml services are running."
        )

    # Return a fresh client for tests
    with httpx.Client(base_url=e2e_backend_url, timeout=30.0) as client:
        yield client


@pytest.fixture
def e2e_keypair():
    """Generate a fresh keypair for e2e testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    # Import here to avoid issues when conftest is loaded
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from identifiers import encode_user_id, encode_space_id

    user_id = encode_user_id(public_key_bytes)
    space_id = encode_space_id(public_key_bytes)

    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_key_bytes,
        'user_id': user_id,
        'space_id': space_id,
    }


@pytest.fixture
def e2e_auth_token(e2e_client, e2e_keypair):
    """
    Authenticate and get a JWT token for e2e tests.

    Returns a dict with token and space_id.
    """
    space_id = e2e_keypair['space_id']
    user_id = e2e_keypair['user_id']
    private_key = e2e_keypair['private']

    # Request challenge
    response = e2e_client.post(
        f"/spaces/{space_id}/auth/challenge",
        json={"public_key": user_id}
    )
    assert response.status_code == 200, f"Challenge request failed: {response.text}"
    challenge_data = response.json()
    challenge = challenge_data['challenge']

    # Sign challenge
    signature_bytes = private_key.sign(challenge.encode('utf-8'))
    signature = base64.b64encode(signature_bytes).decode('utf-8')

    # Verify and get token
    response = e2e_client.post(
        f"/spaces/{space_id}/auth/verify",
        json={
            "public_key": user_id,
            "challenge": challenge,
            "signature": signature
        }
    )
    assert response.status_code == 200, f"Auth verify failed: {response.text}"
    token_data = response.json()

    return {
        'token': token_data['token'],
        'space_id': space_id,
        'user_id': user_id,
        'keypair': e2e_keypair,
    }


@pytest.fixture
def e2e_auth_headers(e2e_auth_token):
    """Get authorization headers for e2e tests"""
    return {"Authorization": f"Bearer {e2e_auth_token['token']}"}
