import type { AuthScreen } from "../../types";
import { Notice } from "../Notice";
import { LoginForm } from "./LoginForm";
import { SignupForm } from "./SignupForm";

type AuthPanelProps = {
	screen: AuthScreen;
	isSubmitting: boolean;
	notice: string;
	isError: boolean;
	onSwitchScreen: (screen: AuthScreen) => void;
	onSubmitLogin: (payload: { username: string; password: string }) => Promise<boolean>;
	onSubmitSignup: (payload: {
		username: string;
		password: string;
		description: string;
	}) => Promise<boolean>;
};

export function AuthPanel({
	screen,
	isSubmitting,
	notice,
	isError,
	onSwitchScreen,
	onSubmitLogin,
	onSubmitSignup,
}: AuthPanelProps) {
	const isLoginScreen = screen === "login";

	return (
		<section className="auth-minimal">
			{isLoginScreen ? (
				<LoginForm
					isSubmitting={isSubmitting}
					onSubmit={onSubmitLogin}
					onSwitchToSignup={() => onSwitchScreen("signup")}
				/>
			) : (
				<SignupForm
					isSubmitting={isSubmitting}
					onSubmit={onSubmitSignup}
					onSwitchToLogin={() => onSwitchScreen("login")}
				/>
			)}

			<Notice message={notice} isError={isError} />
		</section>
	);
}
