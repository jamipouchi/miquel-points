import { fetchJson } from "./client";
import type { AdminPointRequest, AuthUser, PendingUser, PointItem, PointRequest } from "../types";

type SessionResponse = {
	user: AuthUser;
	totalPoints: number;
};

type PointsResponse = {
	totalPoints: number;
	items: PointItem[];
	nextCursor: string | null;
};

export async function fetchCurrentSession() {
	return fetchJson<SessionResponse>("/api/auth/me", undefined, "Unable to load session");
}

export async function loginUser(payload: { username: string; password: string }) {
	return fetchJson<{ ok: true }>(
		"/api/auth/login",
		{
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(payload),
		},
		"Unable to login",
	);
}

export async function signupUser(payload: {
	username: string;
	password: string;
	description: string;
}) {
	return fetchJson<{ ok: true }>(
		"/api/auth/signup",
		{
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(payload),
		},
		"Unable to create user",
	);
}

export async function logoutUser() {
	return fetchJson<{ ok: true }>(
		"/api/auth/logout",
		{
			method: "POST",
		},
		"Unable to logout",
	);
}

export async function fetchPoints(cursor: string | null, limit = 20) {
	const query = new URLSearchParams({ limit: String(limit) });
	if (cursor) {
		query.set("cursor", cursor);
	}

	return fetchJson<PointsResponse>(
		`/api/points?${query.toString()}`,
		undefined,
		"Unable to load points",
	);
}

// --- Point requests (user) ---

export async function createPointRequest(payload: { amount: number; reason: string }) {
	return fetchJson<{ ok: true }>(
		"/api/requests",
		{
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(payload),
		},
		"Unable to create request",
	);
}

export async function fetchMyRequests() {
	return fetchJson<{ requests: PointRequest[] }>("/api/requests", undefined, "Unable to load requests");
}

export async function resubmitRequest(id: string, payload: { amount: number; reason: string }) {
	return fetchJson<{ ok: true }>(
		`/api/requests/${encodeURIComponent(id)}`,
		{
			method: "PUT",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(payload),
		},
		"Unable to resubmit request",
	);
}

// --- Point requests (admin) ---

export async function fetchAdminRequests() {
	return fetchJson<{ requests: AdminPointRequest[] }>("/api/admin/requests", undefined, "Unable to load requests");
}

export async function acceptRequest(id: string, amount: number) {
	return fetchJson<{ ok: true }>(
		`/api/admin/requests/${encodeURIComponent(id)}/accept`,
		{
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ amount }),
		},
		"Unable to accept request",
	);
}

export async function rejectRequest(id: string, payload: { reason: string }) {
	return fetchJson<{ ok: true }>(
		`/api/admin/requests/${encodeURIComponent(id)}/reject`,
		{
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(payload),
		},
		"Unable to reject request",
	);
}

// --- User verification (admin) ---

export async function fetchPendingUsers() {
	return fetchJson<{ users: PendingUser[] }>("/api/admin/users/pending", undefined, "Unable to load users");
}

export async function verifyUser(id: string) {
	return fetchJson<{ ok: true }>(
		`/api/admin/users/${encodeURIComponent(id)}/verify`,
		{
			method: "POST",
		},
		"Unable to verify user",
	);
}
