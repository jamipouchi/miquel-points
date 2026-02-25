export type AuthUser = {
	id: string;
	username: string;
	description: string;
	isAdmin: boolean;
};

export type PointItem = {
	id: string;
	delta: number;
	reason: string;
	createdAt: string;
};

export type PointRequest = {
	id: string;
	amount: number;
	reason: string;
	status: "pending" | "rejected";
	rejectionReason: string | null;
	createdAt: string;
};

export type AdminPointRequest = {
	id: string;
	userId: string;
	username: string;
	amount: number;
	reason: string;
	createdAt: string;
};

export type AuthScreen = "login" | "signup";
