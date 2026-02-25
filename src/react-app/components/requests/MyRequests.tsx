import { FormEvent, useCallback, useEffect, useState } from "react";
import { fetchMyRequests, resubmitRequest } from "../../api/pointsApi";
import type { PointRequest } from "../../types";

export function MyRequests() {
	const [requests, setRequests] = useState<PointRequest[]>([]);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [editAmount, setEditAmount] = useState("");
	const [editReason, setEditReason] = useState("");
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [error, setError] = useState("");

	const load = useCallback(async () => {
		const result = await fetchMyRequests();
		if (result.ok) {
			setRequests(result.data.requests);
		}
	}, []);

	useEffect(() => {
		void load();
	}, [load]);

	function startEdit(req: PointRequest) {
		setEditingId(req.id);
		setEditAmount(String(req.amount));
		setEditReason(req.reason);
		setError("");
	}

	function cancelEdit() {
		setEditingId(null);
		setError("");
	}

	async function handleResubmit(event: FormEvent, id: string) {
		event.preventDefault();
		setIsSubmitting(true);
		setError("");

		const parsed = Number.parseInt(editAmount, 10);
		if (!Number.isFinite(parsed) || parsed <= 0) {
			setError("Amount must be a positive number");
			setIsSubmitting(false);
			return;
		}

		try {
			const result = await resubmitRequest(id, { amount: parsed, reason: editReason.trim() });
			if (!result.ok) {
				setError(result.error);
				return;
			}
			setEditingId(null);
			await load();
		} finally {
			setIsSubmitting(false);
		}
	}

	if (requests.length === 0) return null;

	return (
		<div className="request-section">
			<p className="tiny">my requests</p>
			<ul className="request-list">
				{requests.map((req) => (
					<li key={req.id}>
						{editingId === req.id ? (
							<form className="request-form" onSubmit={(e) => void handleResubmit(e, req.id)}>
								<input
									type="number"
									min="1"
									value={editAmount}
									onChange={(e) => setEditAmount(e.target.value)}
									disabled={isSubmitting}
									required
								/>
								<input
									value={editReason}
									onChange={(e) => setEditReason(e.target.value)}
									disabled={isSubmitting}
									required
									maxLength={280}
								/>
								<div className="row action-row">
									<button className="submit" type="submit" disabled={isSubmitting}>
										resubmit
									</button>
									<button type="button" className="link-button" onClick={cancelEdit} disabled={isSubmitting}>
										cancel
									</button>
								</div>
								{error && <p className="notice error">{error}</p>}
							</form>
						) : (
							<>
								<div className="row row-space">
									<strong>+{req.amount}</strong>
									<span className={`status status-${req.status}`}>{req.status}</span>
								</div>
								<span>{req.reason}</span>
								{req.status === "rejected" && req.rejectionReason && (
									<span className="rejection-reason">rejected: {req.rejectionReason}</span>
								)}
								{req.status === "rejected" && (
									<button type="button" className="link-button" onClick={() => startEdit(req)}>
										edit & resubmit
									</button>
								)}
							</>
						)}
					</li>
				))}
			</ul>
		</div>
	);
}
