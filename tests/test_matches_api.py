import os
import unittest
from unittest.mock import patch

os.environ.setdefault("BETSPORTS_DB", "/tmp/betsports-match-tests.db")
os.environ.setdefault("BETSPORTS_ADMIN_EMAIL", "match-tests@example.invalid")
os.environ.setdefault("BETSPORTS_ADMIN_INITIAL_PASSWORD", "local-test-only-password")

from app import app as flask_app
from app import _apply_rest_filters, matches_for


class MatchApiTests(unittest.TestCase):
    def setUp(self):
        self.client = flask_app.test_client()

    def test_match_list_only_syncs_requested_sport_and_status(self):
        fixture = {
            "id": "test-game",
            "league": "Test League",
            "homeTeam": {"id": "home", "name": "Home"},
            "awayTeam": {"id": "away", "name": "Away"},
            "status": "upcoming",
            "isLive": False,
            "startTime": "2026-09-26T12:00:00Z",
            "odds": {"home": "1.90", "draw": None, "away": "2.10"},
            "score": {"home": 0, "away": 0},
        }
        with patch("app.matches_for", return_value=[fixture]) as fetch_matches:
            response = self.client.get("/rest/v1/matches?sport=eq.football&status=eq.upcoming")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()), 1)
        fetch_matches.assert_called_once_with("football", "upcoming")

    def test_live_boolean_filter_is_case_insensitive(self):
        with flask_app.test_request_context("/rest/v1/matches?is_live=eq.true"):
            rows = _apply_rest_filters([{"is_live": True}, {"is_live": False}])
        self.assertEqual(rows, [{"is_live": True}])

    def test_upcoming_boolean_filter_is_case_insensitive(self):
        with flask_app.test_request_context("/rest/v1/matches?is_live=eq.false"):
            rows = _apply_rest_filters([{"is_live": True}, {"is_live": False}])
        self.assertEqual(rows, [{"is_live": False}])


if __name__ == "__main__":
    unittest.main()
