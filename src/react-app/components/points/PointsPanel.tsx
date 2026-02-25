import { useState } from "react";
import type { AuthUser, PointItem } from "../../types";
import { PointsHistory } from "./PointsHistory";
import { RequestForm } from "../requests/RequestForm";
import { MyRequests } from "../requests/MyRequests";

type PointsPanelProps = {
	user: AuthUser;
	totalPoints: number;
	items: PointItem[];
	nextCursor: string | null;
	isLoadingMore: boolean;
	onLoadMore: () => Promise<void>;
};

export function PointsPanel({
	totalPoints,
	items,
	nextCursor,
	isLoadingMore,
	onLoadMore,
}: PointsPanelProps) {
	const [requestsKey, setRequestsKey] = useState(0);

	return (
		<section className="panel-wide">
			<div className="score-block">
				<p className="tiny">points</p>
				<h1>{totalPoints}</h1>
			</div>

			<RequestForm onCreated={() => setRequestsKey((k) => k + 1)} />
			<MyRequests key={requestsKey} />

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
