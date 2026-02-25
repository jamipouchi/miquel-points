import "./App.css";
import { AppShell } from "./components/AppShell";
import { AuthPanel } from "./components/auth/AuthPanel";
import { PointsPanel } from "./components/points/PointsPanel";
import { usePointsApp } from "./hooks/usePointsApp";

function App() {
  const { screen, user, totalPoints, items, nextCursor, isBooting, isAuthSubmitting, isLoadingMore, notice, isError, switchScreen, submitLogin, submitSignup, performLogout, loadMorePoints } = usePointsApp();

  if (isBooting) {
    return <AppShell><span className="loading">loading...</span></AppShell>;
  }

  if (user) {
    return (
      <AppShell>
        <PointsPanel user={user} totalPoints={totalPoints} items={items} nextCursor={nextCursor} isLoadingMore={isLoadingMore} onLoadMore={loadMorePoints} onLogout={performLogout} />
      </AppShell>
    );
  }

  return (
    <AppShell>
      <AuthPanel screen={screen} isSubmitting={isAuthSubmitting} notice={notice} isError={isError} onSwitchScreen={switchScreen} onSubmitLogin={submitLogin} onSubmitSignup={submitSignup} />
    </AppShell>
  );
}

export default App;
