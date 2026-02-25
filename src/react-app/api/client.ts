type ApiFailure = {
	ok: false;
	error: string;
};

type ApiSuccess<T> = {
	ok: true;
	data: T;
};

export type ApiResult<T> = ApiFailure | ApiSuccess<T>;

function readErrorMessage(body: unknown, fallback: string): string {
	if (
		body &&
		typeof body === "object" &&
		"error" in body &&
		typeof body.error === "string" &&
		body.error.trim().length > 0
	) {
		return body.error;
	}
	return fallback;
}

export async function fetchJson<T>(
	input: RequestInfo | URL,
	init: RequestInit | undefined,
	errorMessage: string,
): Promise<ApiResult<T>> {
	try {
		const response = await fetch(input, init);
		const body = (await response.json().catch(() => null)) as unknown;

		if (!response.ok) {
			return {
				ok: false,
				error: readErrorMessage(body, errorMessage),
			};
		}

		return {
			ok: true,
			data: body as T,
		};
	} catch {
		return {
			ok: false,
			error: "Network error. Please try again.",
		};
	}
}
