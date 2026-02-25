import { useState } from "react";
import "./App.css";
import { AppShell } from "./components/AppShell";
import { AuthPanel } from "./components/auth/AuthPanel";
import { PointsPanel } from "./components/points/PointsPanel";
import { AdminPage } from "./components/admin/AdminPage";
import { usePointsApp } from "./hooks/usePointsApp";

type View = "points" | "admin";

function App() {
  const { screen, user, totalPoints, items, nextCursor, isBooting, isAuthSubmitting, isLoadingMore, notice, isError, switchScreen, submitLogin, submitSignup, performLogout, loadMorePoints } = usePointsApp();
  const [view, setView] = useState<View>("points");

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
          {user.isAdmin && (
            <button type="button" className="link-button" onClick={() => setView(view === "admin" ? "points" : "admin")}>
              {view === "admin" ? "points" : "admin"}
            </button>
          )}
          <button type="button" className="link-button" onClick={() => void performLogout()}>
            logout
          </button>
        </div>
      </nav>
      <main className="content">
        {view === "admin" && user.isAdmin ? (
          <AdminPage />
        ) : (
          <PointsPanel user={user} totalPoints={totalPoints} items={items} nextCursor={nextCursor} isLoadingMore={isLoadingMore} onLoadMore={loadMorePoints} />
        )}
      </main>
    </div>
  );
}

export default App;
