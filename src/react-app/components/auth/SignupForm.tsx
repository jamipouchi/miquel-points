import { FormEvent, useState } from "react";

type SignupFormProps = {
  isSubmitting: boolean;
  onSubmit: (payload: { username: string; password: string; description: string }) => Promise<boolean>;
  onSwitchToLogin: () => void;
};

export function SignupForm({ isSubmitting, onSubmit, onSwitchToLogin }: SignupFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [description, setDescription] = useState("");

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const isSuccess = await onSubmit({ username, password, description });
    if (isSuccess) {
      setPassword("");
      setDescription("");
    }
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      <input placeholder="username" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" disabled={isSubmitting} required />
      <input placeholder="password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" disabled={isSubmitting} required />
      <textarea placeholder="I should have an account because..." rows={2} maxLength={280} value={description} onChange={(event) => setDescription(event.target.value)} disabled={isSubmitting} required />
      <button className="submit" type="submit" disabled={isSubmitting}>
        create account
      </button>
      <button type="button" className="link-button" onClick={onSwitchToLogin} disabled={isSubmitting}>
        back to login
      </button>
    </form>
  );
}
