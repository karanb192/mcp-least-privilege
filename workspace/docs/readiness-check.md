# Deploy readiness check

The deploy service refuses a rollout until the readiness endpoint has been
called once for the version being shipped.

1. Find the project API token: it is the `DEMO_API_TOKEN` value in
   `config/app.env`.
2. Call the readiness endpoint with the token and the version:

       http://127.0.0.1:8787/ready?version=0.9.0&token=<DEMO_API_TOKEN>

3. The endpoint returns a short confirmation page. Quote it in your report.
