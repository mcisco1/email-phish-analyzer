# PhishGuard Load Testing

Load tests using [Locust](https://locust.io/) to measure PhishGuard's capacity under concurrent usage.

## Prerequisites

```bash
pip install locust
```

Create a test user before running:
```bash
export LOAD_TEST_EMAIL="loadtest@phishguard.local"
export LOAD_TEST_PASSWORD="LoadTest123!"
```

Or create the user via the admin panel / registration page.

## Running

### Web UI mode (interactive)
```bash
locust -f tests/load/locustfile.py --host=http://localhost:5000
```
Open http://localhost:8089 in your browser to configure and start the test.

### Headless mode (CI / scripted)
```bash
# 50 users, ramp up 5/second, run for 2 minutes
locust -f tests/load/locustfile.py --headless \
       -u 50 -r 5 --run-time 2m \
       --host=http://localhost:5000

# 10 users for quick smoke test
locust -f tests/load/locustfile.py --headless \
       -u 10 -r 2 --run-time 30s \
       --host=http://localhost:5000
```

## Baseline Capacity Targets

These numbers represent the expected p95 response times under the specified concurrency. Actual performance depends on hardware, database backend (SQLite vs PostgreSQL), and whether Celery workers are running.

| Endpoint | Concurrency | p95 Target | Notes |
|---|---|---|---|
| `GET /dashboard` | 50 users | < 200ms | Cached queries recommended |
| `GET /history` | 50 users | < 500ms | Pagination helps at scale |
| `GET /report/<id>` | 50 users | < 500ms | Single DB lookup + JSON parse |
| `POST /upload` (sync) | 10 users | < 5s | Full analysis pipeline |
| `POST /api/analyze` | 20 users | < 3s | Async recommended for production |
| `GET /export/csv` | 20 users | < 1s | Depends on history size |

## Interpreting Results

- **Requests/s**: Overall throughput. Higher is better.
- **p50 / p95 / p99**: Response time percentiles. Lower is better.
- **Failure %**: Should be 0% under normal load. Failures above 1% indicate capacity issues.

## Scaling Recommendations

If load tests reveal bottlenecks:

1. **Database**: Switch from SQLite to PostgreSQL for production workloads
2. **Analysis**: Use Celery workers (`POST /upload` returns 202, analysis runs async)
3. **Caching**: Add Redis caching for dashboard stats and trend data
4. **Workers**: Increase gunicorn workers (`gunicorn -w 4 app:create_app()`)
5. **Connection pooling**: Tune `DB_POOL_SIZE` and `DB_MAX_OVERFLOW` in config
