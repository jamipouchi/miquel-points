type NoticeProps = {
	message: string;
	isError: boolean;
};

export function Notice({ message, isError }: NoticeProps) {
	if (!message) {
		return null;
	}

	return <p className={isError ? "notice error" : "notice"}>{message}</p>;
}
