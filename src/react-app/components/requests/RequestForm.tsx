import { FormEvent, useState } from "react";
import { createPointRequest } from "../../api/pointsApi";

type RequestFormProps = {
	onCreated: () => void;
};

export function RequestForm({ onCreated }: RequestFormProps) {
	const [open, setOpen] = useState(false);
	const [amount, setAmount] = useState("");
	const [reason, setReason] = useState("");
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [error, setError] = useState("");

	function handleCancel() {
		setOpen(false);
		setAmount("");
		setReason("");
		setError("");
	}

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
			setOpen(false);
			setAmount("");
			setReason("");
			onCreated();
		} finally {
			setIsSubmitting(false);
		}
	}

	if (!open) {
		return (
			<div className="request-section request-cta-wrap">
				<p className="tiny">need points?</p>
				<button type="button" className="request-cta" onClick={() => setOpen(true)}>
					request points
				</button>
			</div>
		);
	}

	return (
		<div className="request-section">
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
				<div className="row action-row">
					<button className="submit" type="submit" disabled={isSubmitting}>
						{isSubmitting ? "sending..." : "request"}
					</button>
					<button type="button" className="link-button" onClick={handleCancel} disabled={isSubmitting}>
						cancel
					</button>
				</div>
			</form>
			{error && <p className="notice error">{error}</p>}
		</div>
	);
}
