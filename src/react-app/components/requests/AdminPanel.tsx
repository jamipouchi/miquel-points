import { FormEvent, useCallback, useEffect, useState } from "react";
import { fetchAdminRequests, acceptRequest, rejectRequest } from "../../api/pointsApi";
import type { AdminPointRequest } from "../../types";

export function AdminPanel() {
	const [requests, setRequests] = useState<AdminPointRequest[]>([]);
	const [rejectingId, setRejectingId] = useState<string | null>(null);
	const [rejectReason, setRejectReason] = useState("");
	const [busyId, setBusyId] = useState<string | null>(null);
	const [error, setError] = useState("");

	const load = useCallback(async () => {
		const result = await fetchAdminRequests();
		if (result.ok) {
			setRequests(result.data.requests);
		}
	}, []);

	useEffect(() => {
		void load();
	}, [load]);

	async function handleAccept(id: string) {
		setBusyId(id);
		setError("");
		try {
			const result = await acceptRequest(id);
			if (!result.ok) {
				setError(result.error);
				return;
			}
			await load();
		} finally {
			setBusyId(null);
		}
	}

	async function handleReject(event: FormEvent, id: string) {
		event.preventDefault();
		setBusyId(id);
		setError("");
		try {
			const result = await rejectRequest(id, { reason: rejectReason.trim() });
			if (!result.ok) {
				setError(result.error);
				return;
			}
			setRejectingId(null);
			setRejectReason("");
			await load();
		} finally {
			setBusyId(null);
		}
	}

	if (requests.length === 0) return null;

	return (
		<div className="request-section">
			<p className="tiny">pending requests</p>
			{error && <p className="notice error">{error}</p>}
			<ul className="request-list">
				{requests.map((req) => (
					<li key={req.id}>
						<div className="row row-space">
							<strong>+{req.amount}</strong>
							<span className="tiny">{req.username}</span>
						</div>
						<span>{req.reason}</span>
						{rejectingId === req.id ? (
							<form onSubmit={(e) => void handleReject(e, req.id)}>
								<input
									placeholder="rejection reason"
									value={rejectReason}
									onChange={(e) => setRejectReason(e.target.value)}
									required
									disabled={busyId === req.id}
								/>
								<div className="row action-row">
									<button className="submit" type="submit" disabled={busyId === req.id}>
										reject
									</button>
									<button
										type="button"
										className="link-button"
										onClick={() => { setRejectingId(null); setRejectReason(""); }}
										disabled={busyId === req.id}
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
									disabled={busyId !== null}
								>
									accept
								</button>
								<button
									type="button"
									className="link-button"
									onClick={() => { setRejectingId(req.id); setError(""); }}
									disabled={busyId !== null}
								>
									reject
								</button>
							</div>
						)}
					</li>
				))}
			</ul>
		</div>
	);
}
