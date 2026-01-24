/**
 * Authentication module for reeeductio Spaces API.
 *
 * Implements challenge-response authentication using Ed25519 signatures.
 */

import {
  signData,
  toUserId,
  decodeBase64,
  encodeBase64,
} from './crypto.js';
import type {
  ChallengeResponse,
  TokenResponse,
  KeyPair,
  ApiError,
} from './types.js';
import { createApiError, AuthenticationError } from './exceptions.js';

/**
 * Authentication session for a space.
 *
 * Handles challenge-response authentication and JWT token management.
 */
export class AuthSession {
  private baseUrl: string;
  private spaceId: string;
  private keyPair: KeyPair;
  private fetchFn: typeof fetch;

  private token: string | null = null;
  private tokenExpiresAt: number | null = null;

  /** Refresh token before this many milliseconds of expiry */
  private readonly refreshBuffer: number = 60_000; // 1 minute

  constructor(
    baseUrl: string,
    spaceId: string,
    keyPair: KeyPair,
    fetchFn: typeof fetch = fetch
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.spaceId = spaceId;
    this.keyPair = keyPair;
    this.fetchFn = fetchFn;
  }

  /**
   * Get the user ID for this session's key pair.
   */
  getUserId(): string {
    return toUserId(this.keyPair.publicKey);
  }

  /**
   * Get a valid JWT token, authenticating if necessary.
   *
   * Automatically refreshes the token if it's about to expire.
   */
  async getToken(): Promise<string> {
    // Check if we need to authenticate or refresh
    if (!this.token || !this.tokenExpiresAt) {
      await this.authenticate();
    } else if (Date.now() >= this.tokenExpiresAt - this.refreshBuffer) {
      // Token is about to expire, try to refresh
      try {
        await this.refresh();
      } catch {
        // Refresh failed, re-authenticate
        await this.authenticate();
      }
    }

    if (!this.token) {
      throw new AuthenticationError('Failed to obtain authentication token');
    }

    return this.token;
  }

  /**
   * Check if we have a valid token.
   */
  hasValidToken(): boolean {
    if (!this.token || !this.tokenExpiresAt) {
      return false;
    }
    return Date.now() < this.tokenExpiresAt - this.refreshBuffer;
  }

  /**
   * Perform full challenge-response authentication.
   */
  async authenticate(): Promise<TokenResponse> {
    // Step 1: Request challenge
    const userId = this.getUserId();
    const challengeResponse = await this.requestChallenge(userId);

    // Step 2: Sign the challenge
    const challengeBytes = decodeBase64(challengeResponse.challenge);
    const signature = await signData(challengeBytes, this.keyPair.privateKey);

    // Step 3: Verify and get token
    const tokenResponse = await this.verifyChallenge(
      userId,
      encodeBase64(signature),
      challengeResponse.challenge
    );

    this.token = tokenResponse.token;
    this.tokenExpiresAt = tokenResponse.expires_at;

    return tokenResponse;
  }

  /**
   * Refresh the current token.
   */
  async refresh(): Promise<TokenResponse> {
    if (!this.token) {
      throw new AuthenticationError('No token to refresh');
    }

    const url = `${this.baseUrl}/spaces/${this.spaceId}/auth/refresh`;

    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      throw createApiError(response.status, error);
    }

    const tokenResponse = (await response.json()) as TokenResponse;
    this.token = tokenResponse.token;
    this.tokenExpiresAt = tokenResponse.expires_at;

    return tokenResponse;
  }

  /**
   * Request an authentication challenge.
   */
  private async requestChallenge(publicKey: string): Promise<ChallengeResponse> {
    const url = `${this.baseUrl}/spaces/${this.spaceId}/auth/challenge`;

    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ public_key: publicKey }),
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      throw createApiError(response.status, error);
    }

    return (await response.json()) as ChallengeResponse;
  }

  /**
   * Verify signed challenge and get JWT token.
   */
  private async verifyChallenge(
    publicKey: string,
    signature: string,
    challenge: string
  ): Promise<TokenResponse> {
    const url = `${this.baseUrl}/spaces/${this.spaceId}/auth/verify`;

    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        public_key: publicKey,
        signature,
        challenge,
      }),
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      throw createApiError(response.status, error);
    }

    return (await response.json()) as TokenResponse;
  }

  /**
   * Parse error response from API.
   */
  private async parseError(response: Response): Promise<ApiError | undefined> {
    try {
      return (await response.json()) as ApiError;
    } catch {
      return undefined;
    }
  }
}

/**
 * Admin authentication session.
 *
 * Uses the /admin/auth/* endpoints for convenience authentication.
 */
export class AdminAuthSession {
  private baseUrl: string;
  private keyPair: KeyPair;
  private fetchFn: typeof fetch;

  private token: string | null = null;
  private tokenExpiresAt: number | null = null;
  private adminSpaceId: string | null = null;

  private readonly refreshBuffer: number = 60_000;

  constructor(baseUrl: string, keyPair: KeyPair, fetchFn: typeof fetch = fetch) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.keyPair = keyPair;
    this.fetchFn = fetchFn;
  }

  /**
   * Get the user ID for this session's key pair.
   */
  getUserId(): string {
    return toUserId(this.keyPair.publicKey);
  }

  /**
   * Get a valid JWT token for admin operations.
   */
  async getToken(): Promise<string> {
    if (!this.token || !this.tokenExpiresAt) {
      await this.authenticate();
    } else if (Date.now() >= this.tokenExpiresAt - this.refreshBuffer) {
      await this.authenticate();
    }

    if (!this.token) {
      throw new AuthenticationError('Failed to obtain admin authentication token');
    }

    return this.token;
  }

  /**
   * Get the admin space ID.
   */
  async getAdminSpaceId(): Promise<string> {
    if (!this.adminSpaceId) {
      await this.fetchAdminSpaceId();
    }

    if (!this.adminSpaceId) {
      throw new AuthenticationError('Failed to obtain admin space ID');
    }

    return this.adminSpaceId;
  }

  /**
   * Perform admin authentication.
   */
  async authenticate(): Promise<TokenResponse> {
    const userId = this.getUserId();

    // Request challenge
    const challengeResponse = await this.requestChallenge(userId);

    // Sign challenge
    const challengeBytes = decodeBase64(challengeResponse.challenge);
    const signature = await signData(challengeBytes, this.keyPair.privateKey);

    // Verify and get token
    const tokenResponse = await this.verifyChallenge(
      userId,
      encodeBase64(signature),
      challengeResponse.challenge
    );

    this.token = tokenResponse.token;
    this.tokenExpiresAt = tokenResponse.expires_at;

    return tokenResponse;
  }

  /**
   * Request admin authentication challenge.
   */
  private async requestChallenge(publicKey: string): Promise<ChallengeResponse> {
    const url = `${this.baseUrl}/admin/auth/challenge`;

    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ public_key: publicKey }),
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      throw createApiError(response.status, error);
    }

    return (await response.json()) as ChallengeResponse;
  }

  /**
   * Verify admin challenge and get JWT.
   */
  private async verifyChallenge(
    publicKey: string,
    signature: string,
    challenge: string
  ): Promise<TokenResponse> {
    const url = `${this.baseUrl}/admin/auth/verify`;

    const response = await this.fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        public_key: publicKey,
        signature,
        challenge,
      }),
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      throw createApiError(response.status, error);
    }

    return (await response.json()) as TokenResponse;
  }

  /**
   * Fetch the admin space ID.
   */
  private async fetchAdminSpaceId(): Promise<void> {
    const token = await this.getToken();
    const url = `${this.baseUrl}/admin/space`;

    const response = await this.fetchFn(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const error = await this.parseError(response);
      throw createApiError(response.status, error);
    }

    const data = (await response.json()) as { space_id: string };
    this.adminSpaceId = data.space_id;
  }

  private async parseError(response: Response): Promise<ApiError | undefined> {
    try {
      return (await response.json()) as ApiError;
    } catch {
      return undefined;
    }
  }
}
