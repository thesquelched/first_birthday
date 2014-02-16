from party import app, initialize
import party.config as config

if __name__ == '__main__':
    initialize()
    if config.FLASK_RUN_EXTERNALLY:
      app.run(host='0.0.0.0', debug=config.FLASK_DEBUG)
    else:
      app.run(debug=config.FLASK_DEBUG)
