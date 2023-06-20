module.exports = {
  apps: [
    {
      name: 'myapp',
      script: './dist/app.js',
      watch: true,
      ignore_watch: ['node_modules'],
      instances: 1,
      exec_mode: 'cluster',
      env: {
        DB_NAME: 'My_DB_NAME',
      },
    },
    {
      name: 'watch-TypeScript',
      script: 'tsc -w',      
    }
  ],
};
