import { useCallback, useEffect, useState } from "react";
import { fetchCurrentSession, fetchLeaderboard, fetchPoints, loginUser, logoutUser, signupUser } from "../api/pointsApi";
import type { AuthScreen, AuthUser, LeaderboardEntry, PointItem } from "../types";

type SubmitLoginPayload = {
  username: string;
  password: string;
};

type SubmitSignupPayload = {
  username: string;
  password: string;
  description: string;
};

export function usePointsApp() {
  const [screen, setScreen] = useState<AuthScreen>("login");
  const [user, setUser] = useState<AuthUser | null>(null);
  const [totalPoints, setTotalPoints] = useState(0);
  const [items, setItems] = useState<PointItem[]>([]);
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [isBooting, setIsBooting] = useState(true);
  const [isAuthSubmitting, setIsAuthSubmitting] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [isLoadingLeaderboard, setIsLoadingLeaderboard] = useState(false);
  const [notice, setNotice] = useState("");
  const [isError, setIsError] = useState(false);

  const resetPointsState = useCallback(() => {
    setTotalPoints(0);
    setItems([]);
    setNextCursor(null);
  }, []);

  const clearNotice = useCallback(() => {
    setNotice("");
    setIsError(false);
  }, []);

  const setErrorNotice = useCallback((message: string) => {
    setNotice(message);
    setIsError(true);
  }, []);

  const setSuccessNotice = useCallback((message: string) => {
    setNotice(message);
    setIsError(false);
  }, []);

  const loadPoints = useCallback(
    async (cursor: string | null) => {
      setIsLoadingMore(Boolean(cursor));

      try {
        const result = await fetchPoints(cursor);
        if (!result.ok) {
          if (!cursor) {
            resetPointsState();
          }
          return false;
        }

        setTotalPoints(result.data.totalPoints);
        setItems((previousItems) => (cursor ? [...previousItems, ...result.data.items] : result.data.items));
        setNextCursor(result.data.nextCursor);
        return true;
      } finally {
        setIsLoadingMore(false);
      }
    },
    [resetPointsState],
  );

  const loadLeaderboard = useCallback(async () => {
    setIsLoadingLeaderboard(true);
    try {
      const result = await fetchLeaderboard();
      if (!result.ok) {
        return false;
      }

      setLeaderboard(result.data.entries);
      return true;
    } finally {
      setIsLoadingLeaderboard(false);
    }
  }, []);

  const bootSession = useCallback(async () => {
    setIsBooting(true);
    clearNotice();

    try {
      const session = await fetchCurrentSession();
      if (!session.ok) {
        setUser(null);
        resetPointsState();
        return false;
      }

      setUser(session.data.user);
      setTotalPoints(session.data.totalPoints);
      await Promise.all([loadPoints(null), loadLeaderboard()]);
      return true;
    } finally {
      setIsBooting(false);
    }
  }, [clearNotice, loadLeaderboard, loadPoints, resetPointsState]);

  useEffect(() => {
    void bootSession();
  }, [bootSession]);

  const switchScreen = useCallback(
    (nextScreen: AuthScreen) => {
      clearNotice();
      setScreen(nextScreen);
    },
    [clearNotice],
  );

  const submitLogin = useCallback(
    async (payload: SubmitLoginPayload) => {
      setIsAuthSubmitting(true);
      clearNotice();

      try {
        const result = await loginUser(payload);
        if (!result.ok) {
          setErrorNotice(result.error === "UNVERIFIED_USER" ? "Pending verification. Ask Miquel to verify your user in DB. \n If you don't know how to ask him, you should not have an account" : result.error);
          return false;
        }

        return bootSession();
      } finally {
        setIsAuthSubmitting(false);
      }
    },
    [bootSession, clearNotice, setErrorNotice],
  );

  const submitSignup = useCallback(
    async (payload: SubmitSignupPayload) => {
      setIsAuthSubmitting(true);
      clearNotice();

      try {
        const result = await signupUser(payload);
        if (!result.ok) {
          setErrorNotice(result.error);
          return false;
        }

        setSuccessNotice("Account created, pending manual verification.");
        setScreen("login");
        return true;
      } finally {
        setIsAuthSubmitting(false);
      }
    },
    [clearNotice, setErrorNotice, setSuccessNotice],
  );

  const performLogout = useCallback(async () => {
    await logoutUser();
    setUser(null);
    resetPointsState();
    setLeaderboard([]);
    setScreen("login");
    clearNotice();
  }, [clearNotice, resetPointsState]);

  const loadMorePoints = useCallback(async () => {
    if (!nextCursor || isLoadingMore) {
      return;
    }

    await loadPoints(nextCursor);
  }, [isLoadingMore, loadPoints, nextCursor]);

  return {
    screen,
    user,
    totalPoints,
    items,
    leaderboard,
    nextCursor,
    isBooting,
    isAuthSubmitting,
    isLoadingMore,
    isLoadingLeaderboard,
    notice,
    isError,
    switchScreen,
    submitLogin,
    submitSignup,
    performLogout,
    loadMorePoints,
  };
}
