import { FormEvent, useCallback, useEffect, useState } from "react";
import { acceptRequest, fetchAdminRequests, fetchPendingUsers, rejectRequest, verifyUser } from "../../api/pointsApi";
import type { AdminPointRequest, PendingUser } from "../../types";

type AdminTab = "users" | "points";

export function AdminPage() {
	const [tab, setTab] = useState<AdminTab>("users");
	const [requests, setRequests] = useState<AdminPointRequest[]>([]);
	const [users, setUsers] = useState<PendingUser[]>([]);
	const [amounts, setAmounts] = useState<Record<string, string>>({});
	const [rejectingId, setRejectingId] = useState<string | null>(null);
	const [rejectReason, setRejectReason] = useState("");
	const [requestBusyId, setRequestBusyId] = useState<string | null>(null);
	const [verifyBusyId, setVerifyBusyId] = useState<string | null>(null);
	const [loadingRequests, setLoadingRequests] = useState(true);
	const [loadingUsers, setLoadingUsers] = useState(true);
	const [error, setError] = useState("");

	const loadRequests = useCallback(async () => {
		setLoadingRequests(true);
		const result = await fetchAdminRequests();
		if (result.ok) {
			setRequests(result.data.requests);
			const initial: Record<string, string> = {};
			for (const req of result.data.requests) {
				initial[req.id] = String(req.amount);
			}
			setAmounts(initial);
		}
		setLoadingRequests(false);
	}, []);

	const loadUsers = useCallback(async () => {
		setLoadingUsers(true);
		const result = await fetchPendingUsers();
		if (result.ok) {
			setUsers(result.data.users);
		}
		setLoadingUsers(false);
	}, []);

	useEffect(() => {
		void Promise.all([loadRequests(), loadUsers()]);
	}, [loadRequests, loadUsers]);

	function setAmount(id: string, value: string) {
		setAmounts((prev) => ({ ...prev, [id]: value }));
	}

	async function handleAccept(id: string) {
		const parsed = Number.parseInt(amounts[id] ?? "0", 10);
		if (!Number.isFinite(parsed) || parsed <= 0) {
			setError("Amount must be a positive number");
			return;
		}
		setRequestBusyId(id);
		setError("");
		try {
			const result = await acceptRequest(id, parsed);
			if (!result.ok) {
				setError(result.error);
				return;
			}
			await loadRequests();
		} finally {
			setRequestBusyId(null);
		}
	}

	async function handleReject(event: FormEvent, id: string) {
		event.preventDefault();
		setRequestBusyId(id);
		setError("");
		try {
			const result = await rejectRequest(id, { reason: rejectReason.trim() });
			if (!result.ok) {
				setError(result.error);
				return;
			}
			setRejectingId(null);
			setRejectReason("");
			await loadRequests();
		} finally {
			setRequestBusyId(null);
		}
	}

	async function handleVerify(id: string) {
		setVerifyBusyId(id);
		setError("");
		try {
			const result = await verifyUser(id);
			if (!result.ok) {
				setError(result.error);
				return;
			}
			await loadUsers();
		} finally {
			setVerifyBusyId(null);
		}
	}

	return (
		<section className="panel-wide">
			<div className="row admin-tabs">
				<button
					type="button"
					className={`link-button admin-tab ${tab === "users" ? "is-active" : ""}`}
					onClick={() => setTab("users")}
				>
					user verification
				</button>
				<button
					type="button"
					className={`link-button admin-tab ${tab === "points" ? "is-active" : ""}`}
					onClick={() => setTab("points")}
				>
					points verification
				</button>
			</div>

			{error && <p className="notice error">{error}</p>}

			{tab === "users" ? (
				loadingUsers ? (
					<p className="loading">loading...</p>
				) : users.length === 0 ? (
					<p className="empty-msg">no pending users</p>
				) : (
					<ul className="request-list">
						{users.map((user) => (
							<li key={user.id}>
								<div className="row row-space">
									<span className="tiny">{user.username}</span>
									<span className="tiny">{new Date(user.createdAt).toLocaleDateString()}</span>
								</div>
								<span>{user.description}</span>
								<div className="row action-row">
									<button
										type="button"
										className="submit"
										onClick={() => void handleVerify(user.id)}
										disabled={verifyBusyId !== null}
									>
										{verifyBusyId === user.id ? "verifying..." : "verify"}
									</button>
								</div>
							</li>
						))}
					</ul>
				)
			) : loadingRequests ? (
				<p className="loading">loading...</p>
			) : requests.length === 0 ? (
				<p className="empty-msg">no pending requests</p>
			) : (
				<ul className="request-list">
					{requests.map((req) => (
						<li key={req.id}>
							<div className="row row-space">
								<span className="tiny">{req.username}</span>
								<span className="tiny">{new Date(req.createdAt).toLocaleDateString()}</span>
							</div>
							<span>{req.reason}</span>
							<input
								type="number"
								min="1"
								value={amounts[req.id] ?? String(req.amount)}
								onChange={(e) => setAmount(req.id, e.target.value)}
								disabled={requestBusyId !== null}
							/>
							{rejectingId === req.id ? (
								<form onSubmit={(e) => void handleReject(e, req.id)}>
									<input
										placeholder="rejection reason"
										value={rejectReason}
										onChange={(e) => setRejectReason(e.target.value)}
										required
										disabled={requestBusyId === req.id}
									/>
									<div className="row action-row">
										<button className="submit" type="submit" disabled={requestBusyId === req.id}>
											reject
										</button>
										<button
											type="button"
											className="link-button"
											onClick={() => { setRejectingId(null); setRejectReason(""); }}
											disabled={requestBusyId === req.id}
										>
											cancel
										</button>
									</div>
								</form>
							) : (
								<div className="row action-row">
									<button
										type="button"
										className="submit"
										onClick={() => void handleAccept(req.id)}
										disabled={requestBusyId !== null}
									>
										accept
									</button>
									<button
										type="button"
										className="link-button"
										onClick={() => { setRejectingId(req.id); setError(""); }}
										disabled={requestBusyId !== null}
									>
										reject
									</button>
								</div>
							)}
						</li>
					))}
				</ul>
			)}
		</section>
	);
}
