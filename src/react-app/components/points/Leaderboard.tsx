import type { LeaderboardEntry } from "../../types";

type LeaderboardProps = {
	entries: LeaderboardEntry[];
	currentUserId: string;
	isLoading: boolean;
};

export function Leaderboard({ entries, currentUserId, isLoading }: LeaderboardProps) {
	return (
		<section className="leaderboard-section">
			<div className="row row-space">
				<p className="tiny">leaderboard</p>
				<p className="tiny">first to 100 wins</p>
			</div>

			{isLoading ? (
				<p className="loading">loading leaderboard...</p>
			) : entries.length === 0 ? (
				<p className="empty-msg">no verified users yet</p>
			) : (
				<ol className="leaderboard-list">
					{entries.map((entry) => {
						const isCurrentUser = entry.userId === currentUserId;
						return (
							<li key={entry.userId} className={isCurrentUser ? "is-current" : undefined}>
								<div className="row row-space">
									<div className="row">
										<strong>#{entry.rank}</strong>
										<span>{entry.username}</span>
									</div>
									<strong>{entry.totalPoints}</strong>
								</div>
								<span className="tiny">{entry.description}</span>
							</li>
						);
					})}
				</ol>
			)}
		</section>
	);
}
