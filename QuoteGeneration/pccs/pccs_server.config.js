module.exports = {
  apps : [{
    name: 'pccs',
    script: 'pccs_server.js',
    max_restarts: 5,
    min_uptime: 30000, // min uptime of the app to be considered started

    // Options reference: http://pm2.keymetrics.io/docs/usage/application-declaration/
    interpreter_args: '-r esm',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
  }]
};
