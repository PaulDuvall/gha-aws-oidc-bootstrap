"""
Test for set_github_variable.py
User Story: US-140
"""
import pytest
import sys
from unittest.mock import patch, MagicMock
from pathlib import Path

import src.set_github_variable as set_gv

def test_set_repo_variable_success(monkeypatch, capsys):
    # Patch requests.patch to simulate update success
    mock_patch = MagicMock(return_value=MagicMock(status_code=200, ok=True))
    monkeypatch.setattr(set_gv.requests, "patch", mock_patch)
    # Should not call post
    monkeypatch.setattr(set_gv.requests, "post", MagicMock())
    assert set_gv.set_repo_variable("org", "repo", "VAR", "VAL", "token") is True
    mock_patch.assert_called_once()
    out = capsys.readouterr().out
    assert "✅ Updated variable 'VAR' for org/repo." in out

def test_set_repo_variable_create(monkeypatch, capsys):
    # Patch requests.patch to simulate 404 (not found)
    mock_patch = MagicMock(return_value=MagicMock(status_code=404, ok=False))
    monkeypatch.setattr(set_gv.requests, "patch", mock_patch)
    # Patch requests.post to simulate create success
    mock_post = MagicMock(return_value=MagicMock(status_code=201, ok=True))
    monkeypatch.setattr(set_gv.requests, "post", mock_post)
    assert set_gv.set_repo_variable("org", "repo", "VAR", "VAL", "token") is True
    mock_patch.assert_called_once()
    mock_post.assert_called_once()
    out = capsys.readouterr().out
    assert "✅ Created variable 'VAR' for org/repo." in out

def test_set_repo_variable_failure(monkeypatch, capsys):
    # Patch requests.patch and post to simulate failure
    mock_patch = MagicMock(return_value=MagicMock(status_code=500, ok=False, text="error"))
    monkeypatch.setattr(set_gv.requests, "patch", mock_patch)
    mock_post = MagicMock(return_value=MagicMock(status_code=500, ok=False, text="error"))
    monkeypatch.setattr(set_gv.requests, "post", mock_post)
    assert set_gv.set_repo_variable("org", "repo", "VAR", "VAL", "token") is False
    mock_patch.assert_called_once()
    # Should not call post unless 404
    mock_post.assert_not_called()
    err = capsys.readouterr().err
    assert "❌ Failed to update variable 'VAR' for org/repo" in err
