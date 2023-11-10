# Flask OpenID Connect Application

This is a Flask application that uses OpenID Connect for authentication.

## Requirements

- Python 3.6 or higher
- Flask
- Flask-OIDC
- python-dotenv

## Setup

1. Clone the repository:

```bash
git clone <repository-url>


## Setup

2. Install the dependencies:

```bash
pip install -r requirements.txt
```

3. Set up your environment variables in a `.env` file. You'll need the following:

- `OIDC_CLIENT_SECRETS`: Your OpenID Connect client secrets file. Defaults to `client_secrets.json`.
- `OIDC_ID_TOKEN_COOKIE_SECURE`: Whether the ID token cookie should be secure. Defaults to `True`.
- `OIDC_OPENID_REALM`: Your OpenID realm.
- `SECRET_KEY`: Your Flask application's secret key.
- `OIDC_COOKIE_SECURE`: Whether the OIDC cookie should be secure. Defaults to `True`.
- `OIDC_CALLBACK_ROUTE`: The route for the OIDC callback. Defaults to `/oidc-callback`.
- `DEBUG`: Whether to run the application in debug mode. Defaults to `True`.

4. Run the application:

```bash
python app.py
```


Please replace `<repository-url>` with the actual URL of your repository.