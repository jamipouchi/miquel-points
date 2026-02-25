import { FormEvent, useState } from "react";
import { createPointRequest } from "../../api/pointsApi";

type RequestFormProps = {
	onCreated: () => void;
};

export function RequestForm({ onCreated }: RequestFormProps) {
	const [amount, setAmount] = useState("");
	const [reason, setReason] = useState("");
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [error, setError] = useState("");

	async function handleSubmit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setIsSubmitting(true);
		setError("");

		const parsed = Number.parseInt(amount, 10);
		if (!Number.isFinite(parsed) || parsed <= 0) {
			setError("Amount must be a positive number");
			setIsSubmitting(false);
			return;
		}

		try {
			const result = await createPointRequest({ amount: parsed, reason: reason.trim() });
			if (!result.ok) {
				setError(result.error);
				return;
			}
			setAmount("");
			setReason("");
			onCreated();
		} finally {
			setIsSubmitting(false);
		}
	}

	return (
		<div className="request-section">
			<p className="tiny">request points</p>
			<form className="request-form" onSubmit={handleSubmit}>
				<input
					type="number"
					placeholder="amount"
					min="1"
					value={amount}
					onChange={(e) => setAmount(e.target.value)}
					disabled={isSubmitting}
					required
				/>
				<input
					placeholder="reason"
					value={reason}
					onChange={(e) => setReason(e.target.value)}
					disabled={isSubmitting}
					required
					maxLength={280}
				/>
				<button className="submit" type="submit" disabled={isSubmitting}>
					{isSubmitting ? "sending..." : "request"}
				</button>
			</form>
			{error && <p className="notice error">{error}</p>}
		</div>
	);
}
