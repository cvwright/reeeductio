/**
 * Blob storage helpers for reeeductio.
 *
 * Provides utilities for uploading, downloading, and managing encrypted blobs.
 */

import { computeHash, toBlobId } from './crypto.js';
import type { BlobCreated, ApiError } from './types.js';
import { createApiError, BlobError } from './exceptions.js';

/**
 * Compute blob identifier from content.
 *
 * The blob_id is a content-addressed identifier based on SHA256 hash.
 *
 * @param data - Raw blob data
 * @returns 44-char base64 blob identifier with 'B' prefix
 */
export function computeBlobId(data: Uint8Array): string {
  const hashBytes = computeHash(data);
  return toBlobId(hashBytes);
}

/**
 * Upload encrypted blob to the space.
 *
 * The blob_id is computed from the content hash.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param data - Encrypted blob data
 * @returns BlobCreated with blob_id and size
 */
export async function uploadBlob(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  data: Uint8Array
): Promise<BlobCreated> {
  // Compute blob ID from content
  const blobId = computeBlobId(data);
  const url = `${baseUrl}/spaces/${spaceId}/blobs/${blobId}`;

  const response = await fetchFn(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/octet-stream',
    },
    body: data,
    redirect: 'manual', // Handle redirects manually
  });

  // Handle redirect to S3 (307)
  if (response.status === 307) {
    const redirectUrl = response.headers.get('Location');
    if (!redirectUrl) {
      throw new BlobError('Received 307 redirect but no Location header');
    }

    // Upload to S3 directly (no auth header for presigned URL)
    const s3Response = await fetchFn(redirectUrl, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream',
      },
      body: data,
    });

    if (!s3Response.ok) {
      throw new BlobError(`Failed to upload blob to S3: ${s3Response.status}`);
    }

    return { blob_id: blobId, size: data.length };
  }

  // Handle 409 Conflict (blob already exists - fine for content-addressed storage)
  if (response.status === 409) {
    return { blob_id: blobId, size: data.length };
  }

  if (!response.ok) {
    const error = await parseError(response);
    throw createApiError(response.status, error);
  }

  // Direct upload (201)
  return (await response.json()) as BlobCreated;
}

/**
 * Download encrypted blob from the space.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param blobId - Typed blob identifier
 * @returns Encrypted blob data
 */
export async function downloadBlob(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  blobId: string
): Promise<Uint8Array> {
  const url = `${baseUrl}/spaces/${spaceId}/blobs/${blobId}`;

  const response = await fetchFn(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
    redirect: 'manual',
  });

  // Handle redirect to S3 (307)
  if (response.status === 307) {
    const redirectUrl = response.headers.get('Location');
    if (!redirectUrl) {
      throw new BlobError('Received 307 redirect but no Location header');
    }

    // Download from S3 directly (no auth header for presigned URL)
    const s3Response = await fetchFn(redirectUrl, {
      method: 'GET',
    });

    if (!s3Response.ok) {
      throw new BlobError(`Failed to download blob from S3: ${s3Response.status}`);
    }

    return new Uint8Array(await s3Response.arrayBuffer());
  }

  if (!response.ok) {
    const error = await parseError(response);
    throw createApiError(response.status, error);
  }

  // Direct download (200)
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Delete blob from the space.
 *
 * Only the uploader or space admin can delete a blob.
 *
 * @param fetchFn - Fetch function
 * @param baseUrl - API base URL
 * @param token - JWT bearer token
 * @param spaceId - Typed space identifier
 * @param blobId - Typed blob identifier
 */
export async function deleteBlob(
  fetchFn: typeof fetch,
  baseUrl: string,
  token: string,
  spaceId: string,
  blobId: string
): Promise<void> {
  const url = `${baseUrl}/spaces/${spaceId}/blobs/${blobId}`;

  const response = await fetchFn(url, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const error = await parseError(response);
    throw createApiError(response.status, error);
  }
}

/**
 * Parse error response from API.
 */
async function parseError(response: Response): Promise<ApiError | undefined> {
  try {
    return (await response.json()) as ApiError;
  } catch {
    return undefined;
  }
}
