from party import app, initialize
import party.config as config
from OpenSSL import SSL


if __name__ == '__main__':
    initialize()

    params = dict(
        debug=config.FLASK_DEBUG,
        port=config.FLASK_PORT,
    )

    if config.SSL_ENABLED:
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.use_certificate_chain_file(config.SSL_CERT)
        context.use_privatekey_file(config.SSL_PRIVATE_KEY)

        params['ssl_context'] = context

    if config.FLASK_RUN_EXTERNALLY:
        params['host'] = '0.0.0.0'

    app.run(**params)
