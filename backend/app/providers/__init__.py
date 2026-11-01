"""Providers package — external detection service adapters."""

from backend.app.providers.gemini import GeminiAdapter, GeminiAnalysisResult

__all__ = ["GeminiAdapter", "GeminiAnalysisResult"]
