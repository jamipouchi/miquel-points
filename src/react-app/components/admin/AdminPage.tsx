import { FormEvent, useCallback, useEffect, useState } from "react";
import { fetchAdminRequests, acceptRequest, rejectRequest } from "../../api/pointsApi";
import type { AdminPointRequest } from "../../types";

export function AdminPage() {
	const [requests, setRequests] = useState<AdminPointRequest[]>([]);
	const [amounts, setAmounts] = useState<Record<string, string>>({});
	const [rejectingId, setRejectingId] = useState<string | null>(null);
	const [rejectReason, setRejectReason] = useState("");
	const [busyId, setBusyId] = useState<string | null>(null);
	const [error, setError] = useState("");

	const load = useCallback(async () => {
		const result = await fetchAdminRequests();
		if (result.ok) {
			setRequests(result.data.requests);
			const initial: Record<string, string> = {};
			for (const req of result.data.requests) {
				initial[req.id] = String(req.amount);
			}
			setAmounts(initial);
		}
	}, []);

	useEffect(() => {
		void load();
	}, [load]);

	function setAmount(id: string, value: string) {
		setAmounts((prev) => ({ ...prev, [id]: value }));
	}

	async function handleAccept(id: string) {
		const parsed = Number.parseInt(amounts[id] ?? "0", 10);
		if (!Number.isFinite(parsed) || parsed <= 0) {
			setError("Amount must be a positive number");
			return;
		}
		setBusyId(id);
		setError("");
		try {
			const result = await acceptRequest(id, parsed);
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

	return (
		<section className="panel-wide">
			{error && <p className="notice error">{error}</p>}

			{requests.length === 0 ? (
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
								disabled={busyId !== null}
							/>
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
			)}
		</section>
	);
}
