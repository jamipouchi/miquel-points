import { useCallback, useEffect, useState } from "react";
import "./App.css";
import { AppShell } from "./components/AppShell";
import { AuthPanel } from "./components/auth/AuthPanel";
import { PointsPanel } from "./components/points/PointsPanel";
import { Leaderboard } from "./components/points/Leaderboard";
import { AdminPage } from "./components/admin/AdminPage";
import { usePointsApp } from "./hooks/usePointsApp";

type View = "points" | "admin" | "leaderboard";

function getInitialView(): View {
  if (window.location.pathname === "/leaderboard") return "leaderboard";
  return "points";
}

function App() {
  const { screen, user, totalPoints, items, leaderboard, nextCursor, isBooting, isAuthSubmitting, isLoadingMore, isLoadingLeaderboard, notice, isError, switchScreen, submitLogin, submitSignup, performLogout, loadMorePoints } = usePointsApp();
  const [view, setView] = useState<View>(getInitialView);

  const navigate = useCallback((next: View) => {
    const path = next === "leaderboard" ? "/leaderboard" : "/";
    window.history.pushState(null, "", path);
    setView(next);
  }, []);

  useEffect(() => {
    const onPopState = () => setView(getInitialView());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  if (isBooting) {
    return <AppShell><span className="loading">loading...</span></AppShell>;
  }

  if (!user) {
    return (
      <AppShell>
        <AuthPanel screen={screen} isSubmitting={isAuthSubmitting} notice={notice} isError={isError} onSwitchScreen={switchScreen} onSubmitLogin={submitLogin} onSubmitSignup={submitSignup} />
      </AppShell>
    );
  }

  return (
    <div className="app-layout">
      <nav className="navbar">
        <span className="tiny">{user.username}</span>
        <div className="row">
          {view !== "leaderboard" && (
            <button
              type="button"
              className="icon-button"
              title="leaderboard"
              onClick={() => navigate("leaderboard")}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <rect x="1" y="7" width="4" height="8" rx="0.5" />
                <rect x="6" y="3" width="4" height="12" rx="0.5" />
                <rect x="11" y="5" width="4" height="10" rx="0.5" />
              </svg>
            </button>
          )}
          {user.isAdmin && (
            <button type="button" className="link-button" onClick={() => navigate(view === "admin" ? "points" : "admin")}>
              {view === "admin" ? "points" : "admin"}
            </button>
          )}
          <button type="button" className="link-button" onClick={() => void performLogout()}>
            logout
          </button>
        </div>
      </nav>
      <main className="content">
        {view === "leaderboard" ? (
          <div className="panel-wide">
            <Leaderboard
              entries={leaderboard}
              currentUserId={user.id}
              isLoading={isLoadingLeaderboard}
              onBack={() => navigate("points")}
            />
          </div>
        ) : view === "admin" && user.isAdmin ? (
          <AdminPage />
        ) : (
          <PointsPanel
            totalPoints={totalPoints}
            items={items}
            nextCursor={nextCursor}
            isLoadingMore={isLoadingMore}
            onLoadMore={loadMorePoints}
          />
        )}
      </main>
    </div>
  );
}

export default App;
