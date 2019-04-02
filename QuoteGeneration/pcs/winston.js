var winston = require('winston');

var options = {
  file: {
    level: 'error',
    filename: __dirname + `/logs/pcs_server.log`,
    handleExceptions: true,
    json: false,
    colorize: true,
  },
  console: {
    level: 'error',
    handleExceptions: true,
    json: false,
    colorize: true,
  }
};

const { createLogger, format, transports } = require('winston');
const { combine, timestamp, label, prettyPrint } = format;
var logger = winston.createLogger({
  format: combine(
    timestamp(),
    prettyPrint()
  ),
  transports: [
    new winston.transports.File(options.file),
    new winston.transports.Console(options.console)
  ],
  exitOnError: false, // do not exit on handled exceptions
});

logger.stream = {
  write: function(message, encoding) {
    logger.info(message);
  },
};

module.exports = logger;
