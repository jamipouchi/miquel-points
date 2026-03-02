import type { LeaderboardEntry } from "../../types";

type LeaderboardProps = {
	entries: LeaderboardEntry[];
	currentUserId: string;
	isLoading: boolean;
	onBack?: () => void;
};

export function Leaderboard({ entries, currentUserId, isLoading, onBack }: LeaderboardProps) {
	return (
		<section className="leaderboard-section">
			{onBack && (
				<button type="button" className="icon-button leaderboard-back" title="back" onClick={onBack}>
					<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
						<line x1="14" y1="8" x2="2" y2="8" />
						<polyline points="7,3 2,8 7,13" />
					</svg>
				</button>
			)}
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
