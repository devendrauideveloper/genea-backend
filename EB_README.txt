FastAPI on Elastic Beanstalk
----------------------------
Entry point: app.main:app
Procfile:    web: gunicorn -k uvicorn.workers.UvicornWorker -b 127.0.0.1:8000 app.main:app

Environment variables should be configured in the EB console (Configuration > Software).
Do NOT commit secrets in .env to the bundle.
