import { FormEvent, useState } from "react";

type LoginFormProps = {
	isSubmitting: boolean;
	onSubmit: (payload: { username: string; password: string }) => Promise<boolean>;
	onSwitchToSignup: () => void;
};

export function LoginForm({
	isSubmitting,
	onSubmit,
	onSwitchToSignup,
}: LoginFormProps) {
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");

	async function handleSubmit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();

		const isSuccess = await onSubmit({ username, password });
		if (isSuccess) {
			setPassword("");
		}
	}

	return (
		<form className="auth-form" onSubmit={handleSubmit}>
			<input
				placeholder="username"
				value={username}
				onChange={(event) => setUsername(event.target.value)}
				autoComplete="username"
				disabled={isSubmitting}
				required
			/>
			<input
				placeholder="password"
				type="password"
				value={password}
				onChange={(event) => setPassword(event.target.value)}
				autoComplete="current-password"
				disabled={isSubmitting}
				required
			/>
			<button className="submit" type="submit" disabled={isSubmitting}>
				sign in
			</button>
			<button
				type="button"
				className="link-button"
				onClick={onSwitchToSignup}
				disabled={isSubmitting}
			>
				create user
			</button>
		</form>
	);
}
