from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from .config import load_config
from .service import IndexService, ALLOWED_ABSTRACTIONS, ALLOWED_SORTS


def create_app() -> Flask:
    app = Flask(__name__, template_folder=str(Path(__file__).resolve().parent.parent / "templates"), static_folder=str(Path(__file__).resolve().parent.parent / "static"))
    config = load_config()
    service = IndexService(config.index_path)

    @app.before_request
    def _ensure_index() -> None:
        service.ensure_index(config.primary_dataset, config.top25_dataset)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def home():
        index = service.load_index()
        top_entries = index["entries"][:10]
        return render_template("index.html", summary=index["summary"], metadata=index["metadata"], top_entries=top_entries)

    @app.get("/rankings")
    def rankings():
        q = request.args.get("q", "", type=str)
        min_score = request.args.get("min_score", 0.0, type=float)
        top25_only = request.args.get("top25_only", "false").lower() == "true"
        abstraction = request.args.get("abstraction", "", type=str).strip().lower()
        sort = request.args.get("sort", "score_desc", type=str)
        limit = request.args.get("limit", 50, type=int)

        if sort not in ALLOWED_SORTS:
            abort(400, "Invalid sort parameter")
        if abstraction and abstraction not in ALLOWED_ABSTRACTIONS:
            abort(400, "Invalid abstraction parameter")
        if limit < 1 or limit > 200:
            abort(400, "Invalid limit parameter")
        if min_score < 0 or min_score > 100:
            abort(400, "Invalid min_score parameter")
        if len(q) > 100:
            abort(400, "Search term too long")

        index = service.load_index()
        items = service.query_entries(index, q=q, min_score=min_score, top25_only=top25_only, abstraction=abstraction, sort=sort, limit=limit)
        return render_template(
            "rankings.html",
            items=items,
            filters={
                "q": q,
                "min_score": min_score,
                "top25_only": top25_only,
                "abstraction": abstraction,
                "sort": sort,
                "limit": limit,
            },
            abstractions=sorted(ALLOWED_ABSTRACTIONS),
            sorts=sorted(ALLOWED_SORTS),
        )

    @app.get("/cwe/<int:cwe_id>")
    def cwe_detail(cwe_id: int):
        index = service.load_index()
        for entry in index["entries"]:
            if entry["cwe_id"] == cwe_id:
                return render_template("detail.html", entry=entry)
        abort(404)

    @app.get("/summary")
    def summary():
        index = service.load_index()
        return jsonify(index["summary"])

    @app.get("/api/cwes")
    def api_cwes():
        q = request.args.get("q", "", type=str)
        min_score = request.args.get("min_score", 0.0, type=float)
        top25_only = request.args.get("top25_only", "false").lower() == "true"
        abstraction = request.args.get("abstraction", "", type=str).strip().lower()
        sort = request.args.get("sort", "score_desc", type=str)
        limit = request.args.get("limit", 50, type=int)
        index = service.load_index()
        items = service.query_entries(index, q=q, min_score=min_score, top25_only=top25_only, abstraction=abstraction, sort=sort, limit=limit)
        return jsonify({"count": len(items), "items": items})

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", title="Bad request", message=str(error)), 400

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", title="Not found", message="The requested resource was not found."), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template("error.html", title="Server error", message="The application could not process the request."), 500

    return app
