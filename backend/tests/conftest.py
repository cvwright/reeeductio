"""
Shared pytest fixtures for backend tests
"""
import sys
import os
import tempfile
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sqlite_message_store import SqliteMessageStore
from sqlite_state_store import SqliteStateStore
from crypto import CryptoUtils
from authorization import AuthorizationEngine
from identifiers import encode_channel_id, encode_user_id
from filesystem_blob_store import FilesystemBlobStore
from sqlite_blob_store import SqliteBlobStore


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_addoption(parser):
    """Add custom command-line options for pytest"""
    parser.addoption(
        "--firestore-emulator",
        action="store",
        default="auto",
        help="Firestore emulator mode: auto|testcontainers|external"
    )


@pytest.fixture
def temp_db_path():
    """Create a temporary database file and clean it up after the test"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    yield db_path

    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def temp_blob_dir():
    """Create a temporary directory for blob storage and clean it up after the test"""
    blob_dir = tempfile.mkdtemp()

    yield blob_dir

    # Cleanup
    shutil.rmtree(blob_dir)


@pytest.fixture
def message_store(temp_db_path):
    """Create a SqliteMessageStore instance with temporary storage"""
    return SqliteMessageStore(temp_db_path)


@pytest.fixture
def state_store(temp_db_path):
    """Create a SqliteStateStore instance with temporary storage"""
    return SqliteStateStore(temp_db_path)


@pytest.fixture
def crypto():
    """Create a CryptoUtils instance"""
    return CryptoUtils()


@pytest.fixture
def authz(state_store, crypto):
    """Create an AuthorizationEngine instance"""
    return AuthorizationEngine(state_store, crypto)


@pytest.fixture
def fs_blob_store(temp_blob_dir):
    """Create a FilesystemBlobStore instance with temporary storage"""
    return FilesystemBlobStore(temp_blob_dir)


@pytest.fixture
def db_blob_store(temp_db_path):
    """Create a SqliteBlobStore instance"""
    return SqliteBlobStore(temp_db_path)


@pytest.fixture(params=['filesystem', 'sqlite'])
def any_blob_store(request, temp_blob_dir, temp_db_path):
    """
    Parametrized fixture that provides all blob store implementations.
    Tests using this fixture will run once for each blob store type.
    """
    if request.param == 'filesystem':
        return FilesystemBlobStore(temp_blob_dir)
    elif request.param == 'sqlite':
        return SqliteBlobStore(temp_db_path)
    else:
        raise ValueError(f"Unknown blob store type: {request.param}")


@pytest.fixture
def admin_keypair():
    """Generate an admin keypair for testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_key_bytes,
        'user_id': encode_user_id(public_key_bytes),
        'channel_id': encode_channel_id(public_key_bytes)
    }


@pytest.fixture
def user_keypair():
    """Generate a user keypair for testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    return {
        'private': private_key,
        'public': public_key,
        'public_bytes': public_key_bytes,
        'user_id': encode_user_id(public_key_bytes)
    }


# ============================================================================
# Firestore Emulator Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def firestore_emulator(request):
    """
    Smart Firestore emulator fixture that adapts to environment.

    Modes:
    - auto: Use testcontainers if available, else external (default)
    - testcontainers: Spin up container automatically
    - external: Use existing emulator at localhost:8080

    Usage:
        # Automatic (tries testcontainers, falls back to external)
        pytest backend/tests/test_firestore_stores.py

        # Use docker-compose emulator
        docker-compose up -d firestore-emulator
        pytest --firestore-emulator=external

        # Force testcontainers
        pytest --firestore-emulator=testcontainers
    """
    mode = request.config.getoption("--firestore-emulator")

    if mode == "external":
        # For local dev with docker-compose
        os.environ['FIRESTORE_EMULATOR_HOST'] = 'localhost:8080'
        os.environ['GCLOUD_PROJECT'] = 'test-project'
        yield
        return

    # Try testcontainers first (for CI and auto mode)
    if mode in ("auto", "testcontainers"):
        try:
            from testcontainers.core.container import DockerContainer
            import time

            # Use generic container with Firestore emulator image
            container = DockerContainer("gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators")
            container.with_command("gcloud beta emulators firestore start --host-port=0.0.0.0:8080")
            container.with_exposed_ports(8080)

            container.start()

            # Get the mapped port and set environment variables
            port = container.get_exposed_port(8080)
            os.environ['FIRESTORE_EMULATOR_HOST'] = f'localhost:{port}'
            os.environ['GCLOUD_PROJECT'] = 'test-project'

            # Wait for emulator to be ready
            time.sleep(3)

            yield container

            container.stop()
            return

        except ImportError:
            if mode == "testcontainers":
                pytest.skip("testcontainers not installed (pip install testcontainers)")
            # Fall through to external mode for 'auto'
        except Exception as e:
            if mode == "testcontainers":
                pytest.skip(f"Failed to start Firestore container: {e}")
            # Fall through to external mode for 'auto'

    # Fallback to external emulator (for auto mode when testcontainers fails)
    if os.environ.get('FIRESTORE_EMULATOR_HOST'):
        # Assume external emulator is running
        os.environ['GCLOUD_PROJECT'] = 'test-project'
        yield
    else:
        pytest.skip(
            "Firestore emulator not available. "
            "Run 'docker-compose up -d firestore-emulator' "
            "or install testcontainers: pip install testcontainers[google]"
        )


def _clear_firestore_data(project_id: str = 'test-project'):
    """Helper to delete all Firestore data"""
    from google.cloud import firestore
    import time

    client = firestore.Client(project=project_id)

    # Delete the main 'channels' collection which contains all our data
    # as subcollections (channels/{id}/state and channels/{id}/topics/{id}/messages)
    channels_ref = client.collection('channels')
    _delete_collection(channels_ref, batch_size=100)

    # Give the emulator time to process deletions
    # (Firestore emulator processes deletes asynchronously)
    time.sleep(1.0)


def _delete_collection(coll_ref, batch_size: int = 100):
    """Recursively delete all documents in a collection"""
    docs = coll_ref.limit(batch_size).stream()
    deleted = 0

    for doc in docs:
        # Delete subcollections first
        for subcollection in doc.reference.collections():
            _delete_collection(subcollection, batch_size)

        # Delete the document
        doc.reference.delete()
        deleted += 1

    # Continue if there might be more documents
    if deleted >= batch_size:
        return _delete_collection(coll_ref, batch_size)


@pytest.fixture
def unique_channel_id(request):
    """
    Generate a unique channel ID for each test to avoid conflicts.

    Uses the test name to ensure uniqueness.
    """
    return f"test-{request.node.name}"


@pytest.fixture
def firestore_state_store(firestore_emulator):
    """
    Get FirestoreStateStore for testing.

    Note: Use the unique_channel_id fixture in your tests to avoid
    conflicts between tests when the emulator cleanup is slow.
    """
    from firestore_state_store import FirestoreStateStore

    store = FirestoreStateStore(project_id='test-project')

    yield store

    # Cleanup after test (best effort - may not complete before next test)
    _clear_firestore_data('test-project')


@pytest.fixture
def firestore_message_store(firestore_emulator):
    """
    Get FirestoreMessageStore for testing.

    Note: Use the unique_channel_id fixture in your tests to avoid
    conflicts between tests when the emulator cleanup is slow.
    """
    from firestore_message_store import FirestoreMessageStore

    store = FirestoreMessageStore(project_id='test-project')

    yield store

    # Cleanup after test (best effort - may not complete before next test)
    _clear_firestore_data('test-project')
