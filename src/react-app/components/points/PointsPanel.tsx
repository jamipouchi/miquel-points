import { useState } from "react";
import type { AuthUser, PointItem } from "../../types";
import { PointsHistory } from "./PointsHistory";
import { RequestForm } from "../requests/RequestForm";
import { MyRequests } from "../requests/MyRequests";
import { AdminPanel } from "../requests/AdminPanel";

type PointsPanelProps = {
	user: AuthUser;
	totalPoints: number;
	items: PointItem[];
	nextCursor: string | null;
	isLoadingMore: boolean;
	onLoadMore: () => Promise<void>;
	onLogout: () => Promise<void>;
};

export function PointsPanel({
	user,
	totalPoints,
	items,
	nextCursor,
	isLoadingMore,
	onLoadMore,
	onLogout,
}: PointsPanelProps) {
	const [requestsKey, setRequestsKey] = useState(0);

	return (
		<section className="panel-wide">
			<div className="row row-space top-bar">
				<span className="tiny">{user.username}</span>
				<button type="button" className="link-button" onClick={() => void onLogout()}>
					logout
				</button>
			</div>

			<div className="score-block">
				<p className="tiny">points</p>
				<h1>{totalPoints}</h1>
			</div>

			<RequestForm onCreated={() => setRequestsKey((k) => k + 1)} />
			<MyRequests key={requestsKey} />

			{user.isAdmin && <AdminPanel />}

			{items.length > 0 && <PointsHistory items={items} />}

			{nextCursor ? (
				<button
					type="button"
					className="submit"
					onClick={() => void onLoadMore()}
					disabled={isLoadingMore}
				>
					{isLoadingMore ? "loading..." : "load more"}
				</button>
			) : null}
		</section>
	);
}
