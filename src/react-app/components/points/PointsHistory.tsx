import type { PointItem } from "../../types";

type PointsHistoryProps = {
	items: PointItem[];
};

function formatDelta(delta: number): string {
	return delta > 0 ? `+${delta}` : String(delta);
}

export function PointsHistory({ items }: PointsHistoryProps) {
	return (
		<ul className="history">
			{items.map((item) => (
				<li key={item.id}>
					<span>{new Date(item.createdAt).toLocaleString()}</span>
					<strong>{formatDelta(item.delta)}</strong>
					<span>{item.reason}</span>
				</li>
			))}
		</ul>
	);
}
